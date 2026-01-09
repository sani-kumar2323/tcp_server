

package main

import (
    "database/sql"
    "encoding/json"
    "fmt"
    "log"
    "net"
    "net/http"
    "os"
    "strings"
    "strconv"

    _ "github.com/lib/pq"
)

var db *sql.DB

// -------------------------
// DB CONNECT FUNCTION
// -------------------------
func connectDB() (*sql.DB, error) {
    host := os.Getenv("DB_HOST")
    if host == "" {
        host = "localhost"
    }

    user := os.Getenv("DB_USER")
    if user == "" {
        user = "postgres"
    }

    password := os.Getenv("DB_PASSWORD")
    if password == "" {
        password = "Sani@123"
    }

    dbname := os.Getenv("DB_NAME")
    if dbname == "" {
        dbname = "tcp_db"
    }

    port := os.Getenv("DB_PORT")
    if port == "" {
        port = "5432"
    }

    connStr := fmt.Sprintf(
        "host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
        host, port, user, password, dbname,
    )

    db, err := sql.Open("postgres", connStr)
    if err != nil {
        return nil, err
    }

    return db, db.Ping()
}

// -------------------------
// MAIN
// -------------------------
func main() {
    var err error
    db, err = connectDB()
    if err != nil {
        log.Fatal("DB error:", err)
    }
    fmt.Println("Connected to PostgreSQL")

    go startTCPServer()


    // http.HandleFunc("/api/messages/", getMessages)

     http.HandleFunc("/api/messages", getMessages)
    http.HandleFunc("/api/frames/decoded/all", getDecodedFrames)
   
    fmt.Println("API listening on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

// -------------------------
// TCP SERVER
// -------------------------
func startTCPServer() {
    ln, err := net.Listen("tcp", ":9000")
    if err != nil {
        log.Fatal("TCP error:", err)
    }
    fmt.Println("TCP running on port 9000")

    for {
        conn, err := ln.Accept()
        if err != nil {
            continue
        }
        go handleTCP(conn)
    }
}

func handleTCP(conn net.Conn) {
    defer conn.Close()

    buf := make([]byte, 2048)
    n, _ := conn.Read(buf)
    packet := buf[:n]

    fmt.Printf("Received (%d bytes): % X\n", n, packet)

    if n < 30 {
        fmt.Println("Ignoring short packet")
        return
    }

    if packet[0] != 0x68 {
        fmt.Println("Invalid start flag")
        return
    }

    header := parseFrameHeader(packet)

    // ---- SAVE FRAME ----
    frameID, err := saveFrameToDB(header)
    if err != nil {
        fmt.Println("DB ERROR (frame):", err)
        return
    }

    // ---- DECODE TLV ----
    tlvBytes := hexStringToBytes(header["tlv_hex"].(string))
    decoded := decodeTLV(tlvBytes)

    // ---- SAVE READING ----
    err = saveReadingToDB(frameID, decoded)
    if err != nil {
        fmt.Println("DB ERROR (reading):", err)
    }

    conn.Write([]byte("OK"))
}


// -------------------------
// FRAME PARSER
// -------------------------
func parseFrameHeader(packet []byte) map[string]interface{} {
    header := make(map[string]interface{})

    header["start_flag"] = fmt.Sprintf("%02X", packet[0])
    header["frame_length"] = int(packet[1])<<8 | int(packet[2])
    header["product_type"] = int(packet[3])

    header["meter_address"] = fmt.Sprintf("%02X%02X%02X%02X%02X%02X%02X%02X",
        packet[4], packet[5], packet[6], packet[7],
        packet[8], packet[9], packet[10], packet[11],
    )

    header["manufacturer_code"] = fmt.Sprintf("%02X%02X", packet[12], packet[13])

    imei := ""
    for _, b := range packet[14:22] {
        imei += fmt.Sprintf("%X%X", b>>4, b&0x0F)
    }
    header["imei"] = imei

    header["protocol_version"] = int(packet[22])
    header["mid"] = int(packet[23])<<8 | int(packet[24])
    header["encryption_flag"] = int(packet[25])
    header["function_code"] = int(packet[26])
    header["tlv_length"] = int(packet[27])<<8 | int(packet[28])

    tlvStart := 29
    tlvEnd := tlvStart + header["tlv_length"].(int)

    header["tlv_hex"] = fmt.Sprintf("% X", packet[tlvStart:tlvEnd])

    header["check_sum"] = fmt.Sprintf("%02X", packet[len(packet)-2])
    header["end_flag"] = fmt.Sprintf("%02X", packet[len(packet)-1])

    return header
}

// -------------------------
// DB INSERT
// -------------------------
func saveFrameToDB(h map[string]interface{}) (int, error) {
    var id int

    err := db.QueryRow(`
        INSERT INTO meter_frames (
            start_flag, frame_length, product_type,
            meter_address, manufacturer_code, imei,
            protocol_version, mid, encryption_flag,
            function_code, tlv_length, tlv_hex,
            check_sum, end_flag
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
        RETURNING id
    `,
        h["start_flag"], h["frame_length"], h["product_type"],
        h["meter_address"], h["manufacturer_code"], h["imei"],
        h["protocol_version"], h["mid"], h["encryption_flag"],
        h["function_code"], h["tlv_length"], h["tlv_hex"],
        h["check_sum"], h["end_flag"],
    ).Scan(&id)

    return id, err
}

//-------------------------
func decodeTLV(tlvBytes []byte) map[string]interface{} {
    result := make(map[string]interface{})
    i := 0

    for i < len(tlvBytes) {
        tag := tlvBytes[i]
        i++

        switch tag {
        case 0x01:
            // header / misc - try to consume 4 bytes if present
            if i+4 <= len(tlvBytes) {
                // store as array for debugging if needed
                result["tag_01"] = []int{int(tlvBytes[i]), int(tlvBytes[i+1]), int(tlvBytes[i+2]), int(tlvBytes[i+3])}
                i += 4
            }

        case 0x02: // total: support 2- or 3-byte forms
            if i+3 <= len(tlvBytes) {
                // prefer 3-byte value
                v := int(tlvBytes[i])<<16 | int(tlvBytes[i+1])<<8 | int(tlvBytes[i+2])
                // if high byte is zero, maybe it's actually 2-byte value -> use lower 16 bits
                if (v>>16) == 0 {
                    v = int(tlvBytes[i+1])<<8 | int(tlvBytes[i+2])
                }
                result["total"] = v
                i += 3
            } else if i+2 <= len(tlvBytes) {
                result["total"] = int(tlvBytes[i])<<8 | int(tlvBytes[i+1])
                i += 2
            } else {
                // malformed - stop
                break
            }

        case 0x04: // flow (4 bytes)
            if i+4 <= len(tlvBytes) {
                v := int(tlvBytes[i])<<24 | int(tlvBytes[i+1])<<16 | int(tlvBytes[i+2])<<8 | int(tlvBytes[i+3])
                result["flow"] = v
                i += 4
            } 

        case 0x08: // battery (1 byte) — your sample shows 08 29 -> 0x29 = 41
            if i < len(tlvBytes) {
                result["battery"] = int(tlvBytes[i])
                i++
            }

        case 0x09: // pressure (1 byte) — sample 09 32 -> 50
            if i < len(tlvBytes) {
                result["pressure"] = int(tlvBytes[i])
                i++
            }

        case 0x0A: // temperature (2 bytes in sample: 00 0F -> 15)
            if i+2 <= len(tlvBytes) {
                // if first byte is 0x00, temperature is second byte
                if tlvBytes[i] == 0x00 {
                    result["temperature_raw"] = int(tlvBytes[i+1])
                } else {
                    // otherwise combine
                    result["temperature_raw"] = int(tlvBytes[i])<<8 | int(tlvBytes[i+1])
                }
                i += 2
            } else if i < len(tlvBytes) {
                result["temperature_raw"] = int(tlvBytes[i])
                i++
            }

        case 0x0C: // magnetic tamper (2 bytes in sample 06 CC)
            if i+2 <= len(tlvBytes) {
                result["magnetic_tamper"] = int(tlvBytes[i])<<8 | int(tlvBytes[i+1])
                i += 2
            }

        case 0x0D: // rssi raw (2 bytes in sample 89 91)
            if i+2 <= len(tlvBytes) {
                result["rssi_raw"] = int(tlvBytes[i])<<8 | int(tlvBytes[i+1])
                i += 2
            }

        case 0x00: // serial: sample shows length-prefixed: 00 09 <6 bytes...>
            if i < len(tlvBytes) {
                ln := int(tlvBytes[i])
                i++
                if i+ln <= len(tlvBytes) {
                    // build hex string like "23365979926F"
                    var sb strings.Builder
                    for k := 0; k < ln; k++ {
                        sb.WriteString(fmt.Sprintf("%02X", tlvBytes[i+k]))
                    }
                    result["serial"] = sb.String()
                    i += ln
                } else {
                    // not enough bytes
                    break
                }
            }

        case 0x13: // valve
            if i < len(tlvBytes) {
                v := int(tlvBytes[i])
                result["valve"] = v

                 if v == 0 {
                    result["valve"] = "OPEN"
                } else {
                    result["valve"] = "CLOSED/TAMPER"
                }
                i++
            }

        case 0x17: // firmware (1 byte)
            if i < len(tlvBytes) {
                result["firmware"] = int(tlvBytes[i])
                i++
            }

        case 0x19: // network status (2 bytes in sample 25 11)
            if i+2 <= len(tlvBytes) {
                result["network_status"] = int(tlvBytes[i])<<8 | int(tlvBytes[i+1])
                i += 2
            }

        case 0x30: // timestamp / rtc (3 bytes)
            if i+3 <= len(tlvBytes) {
                result["rtc"] = []int{int(tlvBytes[i]), int(tlvBytes[i+1]), int(tlvBytes[i+2])}
                i += 3
            }

        case 0x1A: // extended status (8 bytes)
            if i+8 <= len(tlvBytes) {
                arr := make([]int, 8)
                for k := 0; k < 8; k++ {
                    arr[k] = int(tlvBytes[i+k])
                }
                result["extended_status_1a"] = arr
                i += 8
            }

        case 0x1B: // model ascii (null terminated)
            start := i
            for i < len(tlvBytes) && tlvBytes[i] != 0x00 {
                i++
            }
            result["model"] = string(tlvBytes[start:i])
            if i < len(tlvBytes) && tlvBytes[i] == 0x00 {
                i++
            }

        case 0x20: // meter_index_20 (4 bytes)
            if i+4 <= len(tlvBytes) {
                result["meter_index_20"] = []int{int(tlvBytes[i]), int(tlvBytes[i+1]), int(tlvBytes[i+2]), int(tlvBytes[i+3])}
                i += 4
            }

        case 0x12: // ext_block_12 (7 bytes)
            if i+7 <= len(tlvBytes) {
                arr := make([]int, 7)
                for k := 0; k < 7; k++ {
                    arr[k] = int(tlvBytes[i+k])
                }
                result["ext_block_12"] = arr
                i += 7
            }

        case 0x1F: // timestamp_1f (9 bytes)
            if i+9 <= len(tlvBytes) {
                arr := make([]int, 9)
                for k := 0; k < 9; k++ {
                    arr[k] = int(tlvBytes[i+k])
                }
                result["timestamp_1f"] = arr
                // optionally extract network_status if stored there
                if len(arr) >= 5 {
                    result["network_status"] = arr[3]<<8 | arr[4]
                }
                i += 9
            }

        default:
            // Unknown tag: we don't know length -> try skip 1 byte to continue parsing
            // (If your TLV is length-prefixed, adapt here to read the length then skip)
            if i < len(tlvBytes) {
                i++
            }
        }
    }

    return result
}


// -------------------------
// SAVE READING (fixed): uses decoded map keys and safe type conversions
// -------------------------
func saveReadingToDB(frameID int, d map[string]interface{}) error {
    if db == nil {
        return fmt.Errorf("DB not initialized")
    }

    // helper: interface{} → int64
    toInt := func(v interface{}) int64 {
        if v == nil {
            return 0
        }
        switch t := v.(type) {
        case int:
            return int64(t) 
        case int8:
            return int64(t)
        default:
            return 0
        }
    }

    // helper: interface{} → float64
    toFloat := func(v interface{}) float64 {
        if v == nil {
            return 0
        }
        switch t := v.(type) {
        case int:
            return float64(t)
        default:
            return 0
        }
    }

    // helper: interface{} → string
    toString := func(v interface{}) string {
        if v == nil {
            return ""
        }
        switch t := v.(type) {
        case string:
            return t
        case fmt.Stringer:
            return t.String()
        default:
            return fmt.Sprintf("%v", v)
        }
    }

    // Extract decoded TLV values
    total := toInt(d["total"])
    flow := toInt(d["flow"])
    battery := toFloat(d["battery"])
    pressure := toInt(d["pressure"])
    firmware := toInt(d["firmware"])
    valveStatusRaw := toInt(d["valve_status_raw"])
    valve := toString(d["valve"])
    magneticTamper := toInt(d["magnetic_tamper"])
    networkStatus := toInt(d["network_status"])
    temperatureRaw := toInt(d["temperature_raw"])
    serial := toString(d["serial"])
    rssiRaw := toInt(d["rssi_raw"])

    // Insert decoded values into messages table
    _, err := db.Exec(`
        INSERT INTO messages (
            frame_id,
            serial,
            total,
            flow,
            battery,
            pressure,
            firmware,
            valve_status_raw,
            valve,
            magnetic_tamper,
            network_status,
            temperature_raw,
            rssi_raw,
            created_at
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13, NOW()
        )
    `,
        frameID,
        serial,
        total,
        flow,
        battery,
        pressure,
        firmware,       // INT
        valveStatusRaw, // INT
        valve,          // STRING
        magneticTamper,
        networkStatus,
        temperatureRaw,
        rssiRaw,
    )

    if err != nil {
        return fmt.Errorf("saveReadingToDB error: %w", err)
    }

    return nil
}



// -------------------------
// HEX UTIL
// -------------------------
func hexStringToBytes(s string) []byte {
    parts := strings.Split(s, " ")
    var b []byte
    for _, p := range parts {
        val, _ := strconv.ParseUint(p, 16, 8)
        b = append(b, byte(val))
    }
    return b
}

// -------------------------
// API: DECODED FRAMES
// -------------------------
func getDecodedFrames(w http.ResponseWriter, r *http.Request) {
    rows, err := db.Query(`
        SELECT id, meter_address, imei, tlv_hex, created_at
        FROM meter_frames ORDER BY id DESC
    `)
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    defer rows.Close()

    type Frame struct {
        ID           int                    `json:"id"`
        MeterAddress string                 `json:"meter_address"`
        IMEI         string                 `json:"imei"`
        TLVHex       string                 `json:"tlv_hex"`
        Decoded      map[string]interface{} `json:"decoded"`
        CreatedAt    string                 `json:"created_at"`
    }

    var list []Frame

    for rows.Next() {
        var id int
        var addr, imei, tlv, created string

        rows.Scan(&id, &addr, &imei, &tlv, &created)

        decoded := decodeTLV(hexStringToBytes(tlv))

        list = append(list, Frame{
            ID:           id,
            MeterAddress: addr,
            IMEI:         imei,
            TLVHex:       tlv,
            Decoded:      decoded,
            CreatedAt:    created,
        })
    }

    json.NewEncoder(w).Encode(list)
}

//-------------------------
//API: MESSAGES WITH DECODED TLV
//-------------------------


func getMessages(w http.ResponseWriter, r *http.Request) {

    rows, err := db.Query(`
        SELECT 
            id, 
            frame_id, 
            total, 
            flow, 
            battery, 
            pressure, 
            firmware,
            valve_status_raw, 
            valve, 
            magnetic_tamper, 
            network_status,
            temperature_raw,
            rssi_raw
            serial,
            created_at
        FROM messages
        ORDER BY id DESC
    `)
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    defer rows.Close()

    type Msg struct {
        ID             int         `json:"id"`
        FrameID        int         `json:"frame_id"`
        Total          int64       `json:"total"`
        Flow           int64       `json:"flow"`
        Battery        float64     `json:"battery"`
        Pressure       int         `json:"pressure"`
        Firmware       int      `json:"firmware"`
        ValveStatusRaw int64       `json:"valve_status_raw"`
        Valve          string      `json:"valve"`
        MagneticTamper int         `json:"magnetic_tamper"`
        NetworkStatus  int64       `json:"network_status"`
        TemperatureRaw int64       `json:"temperature_raw"`
        Serial         string      `json:"serial"`
        Rssi_raw        int64      `json:"rssi_raw"`
        CreatedAt      string      `json:"created_at"`
    }

    var list []Msg

    for rows.Next() {
        var m Msg
        err := rows.Scan(
            &m.ID,
            &m.FrameID,
            &m.Total,
            &m.Flow,
            &m.Battery,
            &m.Pressure,
            &m.Firmware,
            &m.ValveStatusRaw,
            &m.Valve,
            &m.MagneticTamper,
            &m.NetworkStatus,
            &m.TemperatureRaw,
            &m.Serial,
            &m.Rssi_raw,
            &m.CreatedAt,
        )
        if err != nil {
            http.Error(w, err.Error(), 500)
            return
        }

        list = append(list, m)
    }

   
    json.NewEncoder(w).Encode(list)
}


















// package main

// import (
//     "database/sql"
//     "encoding/hex"
//     "encoding/json"
//     "fmt"
//     "log"
//     "net"
//     "net/http"
//     "os"
//     "strings"

//     _ "github.com/lib/pq"
// )

// var db *sql.DB

// // ----------------------------------------------------
// // DB CONNECT
// // ----------------------------------------------------
// func connectDB() (*sql.DB, error) {
//     host := getenv("DB_HOST", "localhost")
//     port := getenv("DB_PORT", "5432")
//     user := getenv("DB_USER", "postgres")
//     pass := getenv("DB_PASSWORD", "Sani@123")
//     name := getenv("DB_NAME", "tcp_db")

//     connStr := fmt.Sprintf(
//         "host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
//         host, port, user, pass, name,
//     )

//     db, err := sql.Open("postgres", connStr)
//     if err != nil {
//         return nil, err
//     }
//     return db, db.Ping()
// }

// func getenv(key, def string) string {
//     v := os.Getenv(key)
//     if v == "" {
//         return def
//     }
//     return v
// }

// // ----------------------------------------------------
// // MAIN
// // ----------------------------------------------------
// func main() {
//     var err error
//     db, err = connectDB()
//     if err != nil {
//         log.Fatal(err)
//     }
//     fmt.Println("Connected to DB")

//     go startTCPServer()

//     http.HandleFunc("/api/messages", getMessages)
//     http.HandleFunc("/api/frames/decoded/all", getDecodedFrames)

//     fmt.Println("API running :8080")
//     log.Fatal(http.ListenAndServe(":8080", nil))
// }

// // ----------------------------------------------------
// // TCP SERVER
// // ----------------------------------------------------
// func startTCPServer() {
//     ln, err := net.Listen("tcp", ":9000")
//     if err != nil {
//         log.Fatal(err)
//     }
//     fmt.Println("TCP running :9000")

//     for {
//         conn, err := ln.Accept()
//         if err == nil {
//             go handleTCP(conn)
//         }
//     }
// }

// func handleTCP(conn net.Conn) {
//     defer conn.Close()

//     buf := make([]byte, 2048)
//     n, _ := conn.Read(buf)
//     if n < 40 {
//         return
//     }

//     packet := buf[:n]
//     fmt.Printf("RX (%d bytes): % X\n", n, packet)

//     header := parseFrameHeader(packet)

//     frameID, err := saveFrameToDB(header)
//     if err != nil {
//         fmt.Println("FRAME SAVE ERR:", err)
//         return
//     }

//     tlvBytes := hexStringToBytes(header["tlv_hex"].(string))
//     decoded := decodeTLV(tlvBytes)

//     err = saveReadingToDB(decoded, frameID)
//     if err != nil {
//         fmt.Println("READING SAVE ERR:", err)
//     }

//     conn.Write([]byte("OK"))
// }

// // ----------------------------------------------------
// // FRAME PARSER
// // ----------------------------------------------------
// func parseFrameHeader(p []byte) map[string]interface{} {
//     h := make(map[string]interface{})

//     h["start_flag"] = fmt.Sprintf("%02X", p[0])
//     h["frame_length"] = int(p[1])<<8 | int(p[2])
//     h["product_type"] = int(p[3])

//     h["meter_address"] = fmt.Sprintf(
//         "%02X%02X%02X%02X%02X%02X%02X%02X",
//         p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11],
//     )

//     h["manufacturer_code"] = fmt.Sprintf("%02X%02X", p[12], p[13])

//     // IMEI
//     imei := ""
//     for _, b := range p[14:22] {
//         imei += fmt.Sprintf("%X%X", b>>4, b&0x0F)
//     }
//     h["imei"] = imei

//     h["protocol_version"] = int(p[22])
//     h["mid"] = int(p[23])<<8 | int(p[24])
//     h["encryption_flag"] = int(p[25])
//     h["function_code"] = int(p[26])

//     tlvLen := int(p[27])<<8 | int(p[28])
//     h["tlv_length"] = tlvLen

//     tlvStart := 29
//     tlvEnd := tlvStart + tlvLen
//     h["tlv_hex"] = fmt.Sprintf("% X", p[tlvStart:tlvEnd])

//     h["checksum"] = fmt.Sprintf("%02X", p[len(p)-2])
//     h["end_flag"] = fmt.Sprintf("%02X", p[len(p)-1])

//     return h
// }

// // ----------------------------------------------------
// // SAVE FRAME
// // ----------------------------------------------------
// func saveFrameToDB(h map[string]interface{}) (int, error) {
//     sql := `
//         INSERT INTO meter_frames (
//             start_flag, frame_length, product_type, meter_address,
//             manufacturer_code, imei, protocol_version, mid,
//             encryption_flag, function_code, tlv_length, tlv_hex,
//             checksum, end_flag
//         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
//         RETURNING id
//     `
//     var id int
//     err := db.QueryRow(sql,
//         h["start_flag"], h["frame_length"], h["product_type"],
//         h["meter_address"], h["manufacturer_code"], h["imei"],
//         h["protocol_version"], h["mid"], h["encryption_flag"],
//         h["function_code"], h["tlv_length"], h["tlv_hex"],
//         h["checksum"], h["end_flag"],
//     ).Scan(&id)
//     return id, err
// }

// // ----------------------------------------------------
// // SAVE READING
// // ----------------------------------------------------
// func saveReadingToDB(d map[string]interface{}, frameID int) error {
//     sql := `
//         INSERT INTO messages (
//             id, total, flow, battery, pressure, temperature_raw,
//             magnetic_tamper, rssi_raw, serial, valve, firmware,
//             network_status
//         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
//     `
//     _, err := db.Exec(sql,
//         frameID,
//         d["total"],
//         d["flow"],
//         d["battery"],
//         d["pressure"],
//         d["temperature"],
//         d["magnetic_tamper"],
//         d["rssi_raw"],
//         d["serial"],
//         d["valve"],
//         d["firmware"],
//         d["network_status"],
//     )
//     return err
// }

// // ----------------------------------------------------
// // TLV DECODER (COMPLETE + MATCHES YOUR OUTPUT)
// // ----------------------------------------------------
// func decodeTLV(tlv []byte) map[string]interface{} {
//     result := make(map[string]interface{})
//     i := 0

//     for i < len(tlv) {
//         id := tlv[i]
//         i++

//     switch id {

//     case 0x01:
//     // Example: Status + Flags (2 bytes)
//     result["status"] = tlv[i]
//     result["flags"] = tlv[i+1]
//     i += 2

// case 0x02:
//     // Total (4 bytes) — always treat as uint32
//     if i+4 <= len(tlv) {
//         val := uint32(tlv[i])<<24 | uint32(tlv[i+1])<<16 | uint32(tlv[i+2])<<8 | uint32(tlv[i+3])
//         result["total"] = val
//         i += 4
//     }

// case 0x04:
//     // Flow (4 bytes)
//     if i+4 <= len(tlv) {
//         val := uint32(tlv[i])<<24 | uint32(tlv[i+1])<<16 | uint32(tlv[i+2])<<8 | uint32(tlv[i+3])
//         result["flow"] = val
//         i += 4
//     }

// case 0x08:
//     result["battery"] = int(tlv[i])
//     i += 1

// case 0x09:
//     result["pressure"] = int(tlv[i])
//     i += 1

// case 0x0A:
//     result["temperature"] = int(tlv[i])
//     i += 2

// case 0x0C:
//     val := int(tlv[i])<<8 | int(tlv[i+1])
//     result["magnetic_tamper"] = val
//     i += 2

// case 0x0D:
//     val := int(tlv[i])<<8 | int(tlv[i+1])
//     result["rssi_raw"] = val
//     i += 2

// case 0x00:
//     serial := fmt.Sprintf("%X%X%X%X%X%X%X",
//         tlv[i], tlv[i+1], tlv[i+2], tlv[i+3],
//         tlv[i+4], tlv[i+5], tlv[i+6],
//     )
//     result["serial"] = serial
//     i += 7

// case 0x13:
//     result["valve"] = int(tlv[i])
//     i += 1

// case 0x17:
//     result["firmware"] = int(tlv[i])
//     i += 1

// case 0x19:
//     arr := []int{int(tlv[i]), int(tlv[i+1])}
//     result["network_status"] = arr
//     i += 2

// case 0x30:
//     arr := []int{int(tlv[i]), int(tlv[i+1]), int(tlv[i+2])}
//     result["rtc"] = arr
//     i += 3

// case 0x1A:
//     arr := make([]int, 8)
//     for k := 0; k < 8; k++ {
//         arr[k] = int(tlv[i+k])
//     }
//     result["extended_status_1a"] = arr
//     i += 8

// case 0x1B:
//     model := string(tlv[i : i+10])
//     result["model"] = strings.Trim(model, "\x00")
//     i += 10

// case 0x20:
//     arr := []int{int(tlv[i]), int(tlv[i+1]), int(tlv[i+2]), int(tlv[i+3])}
//     result["meter_index_20"] = arr
//     i += 4

// case 0x12:
//     arr := make([]int, 7)
//     for k := 0; k < 7; k++ {
//         arr[k] = int(tlv[i+k])
//     }
//     result["ext_block_12"] = arr
//     i += 7

// case 0x1F:
//     arr := make([]int, 9)
//     for k := 0; k < 9; k++ {
//         arr[k] = int(tlv[i+k])
//     }
//     result["timestamp_1f"] = arr
//     i += 9

// default:
//     i++
// }

//     }
//     return result
// }


// // func appendIntArray(v interface{}, x int) []int {
// //     if v == nil {
// //         return []int{x}
// //     }
// //     arr := v.([]int)
// //     return append(arr, x)
// // }

// // ----------------------------------------------------
// // UTILS
// // ----------------------------------------------------
// func hexStringToBytes(s string) []byte {
//     s = strings.ReplaceAll(s, " ", "")
//     b, _ := hex.DecodeString(s)
//     return b
// }

// // ----------------------------------------------------
// // API: DECODED FRAMES
// // ----------------------------------------------------
// func getDecodedFrames(w http.ResponseWriter, r *http.Request) {
//     rows, _ := db.Query(`SELECT id, meter_address, imei, tlv_hex, created_at FROM meter_frames ORDER BY id DESC`)
//     defer rows.Close()

//     type Frame struct {
//         ID          int                    `json:"id"`
//         MeterAddr   string                 `json:"meter_address"`
//         IMEI        string                 `json:"imei"`
//         TLVHex      string                 `json:"tlv_hex"`
//         Decoded     map[string]interface{} `json:"decoded"`
//         Created     string                 `json:"created_at"`
//     }

//     var list []Frame

//     for rows.Next() {
//         var f Frame
//         rows.Scan(&f.ID, &f.MeterAddr, &f.IMEI, &f.TLVHex, &f.Created)
//         f.Decoded = decodeTLV(hexStringToBytes(f.TLVHex))
//         list = append(list, f)
//     }
//     json.NewEncoder(w).Encode(list)
// }

// // ----------------------------------------------------
// // API: MESSAGES
// // ----------------------------------------------------
// func getMessages(w http.ResponseWriter, r *http.Request) {
//     rows, _ := db.Query(`
//         SELECT m.id, m.total, m.flow, m.battery, m.pressure,
//                m.temperature_raw, m.magnetic_tamper, m.rssi_raw,
//                m.serial, m.valve, m.firmware, m.network_status,
//                m.created_at, f.tlv_hex
//         FROM messages m
//         JOIN meter_frames f ON f.id = m.id
//         ORDER BY m.id DESC
//     `)
//     defer rows.Close()

//     type Msg struct {
//         ID             int                    `json:"id"`
//         Total          int                    `json:"total"`
//         Flow           int                    `json:"flow"`
//         Battery        int                    `json:"battery"`
//         Pressure       int                    `json:"pressure"`
//         Temperature    int                    `json:"temperature"`
//         Tamper         int                    `json:"magnetic_tamper"`
//         RSSI           int                    `json:"rssi_raw"`
//         Serial         string                 `json:"serial"`
//         Valve          int                    `json:"valve"`
//         Firmware       int                    `json:"firmware"`
//         Network        int                    `json:"network_status"`
//         Created        string                 `json:"created_at"`
//         DecodedTLV     map[string]interface{} `json:"decoded"`
//     }

//     var list []Msg

//     for rows.Next() {
//         var m Msg
//         var tlvHex string
//         rows.Scan(
//             &m.ID, &m.Total, &m.Flow, &m.Battery, &m.Pressure,
//             &m.Temperature, &m.Tamper, &m.RSSI, &m.Serial,
//             &m.Valve, &m.Firmware, &m.Network, &m.Created, &tlvHex,
//         )
//         m.DecodedTLV = decodeTLV(hexStringToBytes(tlvHex))
//         list = append(list, m)
//     }

//     json.NewEncoder(w).Encode(list)
// }



















