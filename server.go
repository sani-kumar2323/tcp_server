package main

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq"
	_ "github.com/google/uuid"
)

var db *sql.DB

// -------------------------
// DB CONNECT FUNCTION
// -------------------------
func connectDB() (*sql.DB, error) {
	host := getenv("DB_HOST", "localhost")
	if host == "" {
		host = "localhost"
	}
	user := getenv("DB_USER", "postgres")
	pass := getenv("DB_PASSWORD", "Sani@123")
	name := getenv("DB_NAME", "tcp_db")
	port := getenv("DB_PORT", "5432")

	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, pass, name,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}
	return db, db.Ping()
}

func getenv(k, d string) string {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	return v
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

	buf := make([]byte, 4096)
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

	header["checksum"] = fmt.Sprintf("%02X", packet[len(packet)-2])
	header["end_flag"] = fmt.Sprintf("%02X", packet[len(packet)-1])

	return header
}

// -------------------------
// DB INSERT: meter_frames
// -------------------------
func saveFrameToDB(h map[string]interface{}) (int, error) {
	var id int
	err := db.QueryRow(`
        INSERT INTO meter_frames (
            start_flag, frame_length, product_type,
            meter_address, manufacturer_code, imei,
            protocol_version, mid, encryption_flag,
            function_code, tlv_length, tlv_hex,
            checksum, end_flag, created_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14, now())
        RETURNING id
    `,
		h["start_flag"], h["frame_length"], h["product_type"],
		h["meter_address"], h["manufacturer_code"], h["imei"],
		h["protocol_version"], h["mid"], h["encryption_flag"],
		h["function_code"], h["tlv_length"], h["tlv_hex"],
		h["checksum"], h["end_flag"],
	).Scan(&id)
	return id, err
}

// -------------------------
// DB INSERT: messages (decoded)
// -------------------------
// This will store decoded values into messages table. For array fields we store JSON.
func saveReadingToDB(frameID int, d map[string]interface{}) error {
	// helper to marshal an interface to JSON []byte (or nil)
	toJSON := func(v interface{}) interface{} {
		if v == nil {
			return nil
		}
		b, _ := json.Marshal(v)
		return string(b)
	}

	sqlStmt := `
        INSERT INTO messages (
            frame_id, total, flow, battery, pressure, temperature,
            magnetic_tamper, rssi_raw, serial, valve, firmware,
            network_status, rtc, extended_status_1a, model,
            meter_index_20, counters, ext_block_12, timestamp_1f,
            created_at
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19, now()
        )
    `

	_, err := db.Exec(sqlStmt,
		frameID,
		getInt(d["total"]),      // 2
		getInt(d["flow"]),       // 3
		getInt(d["battery"]),    // 4
		getInt(d["pressure"]),   // 5
		getInt(d["temperature"]),// 6
		getInt(d["magnetic_tamper"]),
		getInt(d["rssi_raw"]),
		getString(d["serial"]),
		getInt(d["valve"]),
		getInt(d["firmware"]),
		getInt(d["network_status"]),
		toJSON(d["rtc"]),
		toJSON(d["extended_status_1a"]),
		getString(d["model"]),
		toJSON(d["meter_index_20"]),
		toJSON(d["counters"]),
		toJSON(d["ext_block_12"]),
		toJSON(d["timestamp_1f"]),
	)

	return err
}

// small helpers
func getInt(v interface{}) int {
	if v == nil {
		return 0
	}
	switch t := v.(type) {
	case int:
		return t
	case int32:
		return int(t)
	case int64:
		return int(t)
	case uint32:
		return int(t)
	case float64:
		return int(t)
	default:
		// try to decode numeric from json.Number or string
		switch s := v.(type) {
		case string:
			i, _ := strconv.Atoi(s)
			return i
		default:
			return 0
		}
	}
}

func getString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}



   



// -------------------------
// TLV DECODER
// -------------------------
// Decodes TLV according to the tags you provided; no duplicate cases.
func decodeTLV(b []byte) map[string]interface{} {
	r := make(map[string]interface{})
	i := 0
	// Initialize counters to zero-array if needed
	r["counters"] = []int{0, 0, 0, 0, 0, 0}

	for i < len(b) {
		tag := b[i]
		i++

		switch tag {
		case 0x01:
			// If tag 0x01 has a known length, handle here.
			// In your example the first bytes looked like: 01 00 46 01 15
			// We'll try to safely consume the next 4 bytes (if available).
			if i+4 <= len(b) {
				r["tag_01"] = []int{int(b[i]), int(b[i+1]), int(b[i+2]), int(b[i+3])}
				i += 4
			}

		case 0x02: // total (2 or 3 bytes depending on device) — your example used 0x80 0x64 (2 bytes) earlier but you specified 32868 (0x8064) previously
			// Handle 2-byte and 3-byte forms: try 3-byte first if available
			if i+3 <= len(b) {
				// If next byte is zero-length marker? We'll attempt 3-bytes safely
				val := int(b[i])<<16 | int(b[i+1])<<8 | int(b[i+2])
				// If val is small and we expect 2-byte, check if the high byte is zero.
				if (val>>16) == 0 {
					// maybe actual was 2-byte value stored; use lower 16 bits
					val = int(b[i+1])<<8 | int(b[i+2])
				}
				r["total"] = val
				i += 3
			} else if i+2 <= len(b) {
				r["total"] = int(b[i])<<8 | int(b[i+1])
				i += 2
			} else {
				// malformed - break
				break
			}

		case 0x04: // flow (4 bytes)
			if i+4 <= len(b) {
				r["flow"] = int(b[i])<<24 | int(b[i+1])<<16 | int(b[i+2])<<8 | int(b[i+3])
				i += 4
			} 

		case 0x08: // battery (1 byte)
			if i < len(b) {
				r["battery"] = int(b[i])
				i++
			}

		case 0x09: // pressure (1 byte)
			if i < len(b) {
				// You had one example 0x09 0x32 -> 50
				r["pressure"] = int(b[i])
				i++
			}

		case 0x0A: // temperature (2 bytes or 1)
			// your sample is 00 0F -> 15
			if i+2 <= len(b) && b[i] == 0x00 {
				// short form
				r["temperature"] = int(b[i+1])
				i += 2
			} else if i < len(b) {
				r["temperature"] = int(b[i])
				i++
			}

		case 0x0C: // magnetic tamper (2 bytes)
			if i+2 <= len(b) {
				r["magnetic_tamper"] = int(b[i])<<8 | int(b[i+1])
				i += 2
			}

		case 0x0D: // rssi (2 bytes)
			if i+2 <= len(b) {
				r["rssi_raw"] = int(b[i])<<8 | int(b[i+1])
				i += 2
			}

		case 0x00: // serial (length prefixed in your sample: 09 then bytes). In sample you had: 00 09 XX XX ...
			// If next byte is length:
			if i < len(b) {
				ln := int(b[i])
				i++
				if i+ln <= len(b) {
					hexStr := ""
					for k := 0; k < ln; k++ {
						hexStr += fmt.Sprintf("%02X", b[i+k])
					}
					r["serial"] = hexStr
					i += ln
				}
			}

		

		case 0x13: // valve (1 byte)
			if i < len(b) {
				r["valve"] = int(b[i])
				i++
			}

		case 0x17: // firmware (1 byte)
			if i < len(b) {
				r["firmware"] = int(b[i])
				i++
			}

		case 0x19: // small network/status block (2-3 bytes)
			// In your sample 19 25 11 -> maybe two bytes of status
			if i+2 <= len(b) {
				r["network_status"] = int(b[i])<<8 | int(b[i+1])
				i += 2
			}

		case 0x30: // RTC or timestamp (3 bytes)
			if i+3 <= len(b) {
				r["rtc"] = []int{int(b[i]), int(b[i+1]), int(b[i+2])}
				i += 3
			}

		case 0x1A: // extended status (8 bytes)
			if i+8 <= len(b) {
				arr := make([]int, 8)
				for k := 0; k < 8; k++ {
					arr[k] = int(b[i+k])
				}
				r["extended_status_1a"] = arr
				i += 8
			}

		case 0x1B: // meter model string - fixed max length 16 in your sample
			// Read bytes until 0x00 or up to 16 bytes safe-guard
			start := i
			for i < len(b) && b[i] != 0x00 && (i-start) < 32 {
				i++
			}
			if i < len(b) && b[i] == 0x00 {
				r["model"] = string(b[start:i])
				i++ // skip 0x00
			} else {
				// fallback
				r["model"] = string(b[start:i])
			}

		case 0x20: // meter_index_20 (4 bytes)
			if i+4 <= len(b) {
				arr := []int{int(b[i]), int(b[i+1]), int(b[i+2]), int(b[i+3])}
				r["meter_index_20"] = arr
				i += 4
			}

		case 0x12: // ext_block_12 (7 bytes per your earlier)
			if i+7 <= len(b) {
				arr := make([]int, 7)
				for k := 0; k < 7; k++ {
					arr[k] = int(b[i+k])
				}
				r["ext_block_12"] = arr
				i += 7
			}

		case 0x1F: // timestamp_1f (9 bytes per your earlier)
			if i+9 <= len(b) {
				arr := make([]int, 9)
				for k := 0; k < 9; k++ {
					arr[k] = int(b[i+k])
				}
				r["timestamp_1f"] = arr
				// network_status sometimes nested in here; keep safe extraction
				if len(arr) >= 5 {
					// example extraction — adapt if your protocol differs
					r["network_status"] = arr[3]<<8 | arr[4]
				}
				i += 9
			}

		default:
			// Many TLV protocols use: tag, length, value. If your TLV uses length, adapt this branch.
			if i < len(b) {
				i++
			}
		}
	}

	return r
}

// -------------------------
// HEX UTIL
// -------------------------
func hexStringToBytes(s string) []byte {
	// Accept both "01 02 AF" and "0102AF"
	s = strings.TrimSpace(s)
	if strings.Contains(s, " ") {
		parts := strings.Split(s, " ")
		b := make([]byte, 0, len(parts))
		for _, p := range parts {
			if p == "" {
				continue
			}
			val, err := strconv.ParseUint(p, 16, 8)
			if err != nil {
				continue
			}
			b = append(b, byte(val))
		}
		return b
	}
	b, _ := hex.DecodeString(s)
	return b
}

// -------------------------
// API: DECODED FRAMES
// -------------------------
func getDecodedFrames(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
        SELECT id, meter_address, imei, tlv_hex,checksum,end_flag created_at
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
		CheckSum     string                  `json:"checksum"`
		EndFlag      string                   `json:"end_flag"`
		// Decoded      map[string]interface{} `json:"decoded"`
		CreatedAt    time.Time              `json:"created_at"`
	}

	var list []Frame

	for rows.Next() {
		var f Frame
		var created sql.NullTime
		rows.Scan(&f.ID, &f.MeterAddress, &f.IMEI, &f.TLVHex,&f.CheckSum,&f.EndFlag, &created)
		if created.Valid {
			f.CreatedAt = created.Time
		}
		// f.Decoded = decodeTLV(hexStringToBytes(f.TLVHex))
		list = append(list, f)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

// -------------------------
// API: MESSAGES with DECODED TLV (read from messages table where we inserted decoded values)
// -------------------------
func getMessages(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
        SELECT id, frame_id, total, flow, battery, pressure, temperature,
               magnetic_tamper, rssi_raw, serial, valve, firmware,
               network_status, rtc, extended_status_1a, model,
               meter_index_20, counters, ext_block_12, timestamp_1f, created_at
        FROM messages
        ORDER BY id DESC
    `)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	type Msg struct {
		ID                int                    `json:"id"`
		FrameID           int                    `json:"frame_id"`
		Total             int                    `json:"total"`
		Flow              int                    `json:"flow"`
		Battery           int                    `json:"battery"`
		Pressure          int                    `json:"pressure"`
		Temperature       int                    `json:"temperature"`
		MagneticTamper    int                    `json:"magnetic_tamper"`
		RSSIRaw           int                    `json:"rssi_raw"`
		Serial            string                 `json:"serial"`
		Valve             int                    `json:"valve"`
		Firmware          int                    `json:"firmware"`
		NetworkStatus     int                    `json:"network_status"`
		RTC               interface{}            `json:"rtc"`
		ExtendedStatus1A  interface{}            `json:"extended_status_1a"`
		Model             string                 `json:"model"`
		MeterIndex20      interface{}            `json:"meter_index_20"`
		Counters          interface{}            `json:"counters"`
		ExtBlock12        interface{}            `json:"ext_block_12"`
		Timestamp1F       interface{}            `json:"timestamp_1f"`
		CreatedAt         time.Time              `json:"created_at"`
		DecodedRawExample map[string]interface{} `json:"decoded_example,omitempty"`
	}

	var list []Msg

	for rows.Next() {
		var m Msg
		var rtcJSON, ext1aJSON, idx20JSON, countersJSON, ext12JSON, t1fJSON sql.NullString
		var created sql.NullTime

		err := rows.Scan(
			&m.ID, &m.FrameID, &m.Total, &m.Flow, &m.Battery, &m.Pressure, &m.Temperature,
			&m.MagneticTamper, &m.RSSIRaw, &m.Serial, &m.Valve, &m.Firmware,
			&m.NetworkStatus, &rtcJSON, &ext1aJSON, &m.Model,
			&idx20JSON, &countersJSON, &ext12JSON, &t1fJSON, &created,
		)
		if err != nil {
			continue
		}
		// if created.Valid {
		// 	m.CreatedAt = created.Time
		// }

		// Unmarshal JSONB/text columns to interface{} so API returns proper arrays
		var tmp interface{}
		if rtcJSON.Valid {
			_ = json.Unmarshal([]byte(rtcJSON.String), &tmp)
			m.RTC = tmp
		}
		if ext1aJSON.Valid {
			_ = json.Unmarshal([]byte(ext1aJSON.String), &tmp)
			m.ExtendedStatus1A = tmp
		}
		if idx20JSON.Valid {
			_ = json.Unmarshal([]byte(idx20JSON.String), &tmp)
			m.MeterIndex20 = tmp
		}
		if countersJSON.Valid {
			_ = json.Unmarshal([]byte(countersJSON.String), &tmp)
			m.Counters = tmp
		}
		if ext12JSON.Valid {
			_ = json.Unmarshal([]byte(ext12JSON.String), &tmp)
			m.ExtBlock12 = tmp
		}
		if t1fJSON.Valid {
			_ = json.Unmarshal([]byte(t1fJSON.String), &tmp)
			m.Timestamp1F = tmp
		}

		// optional: show one example decoded object merged from fields
		m.DecodedRawExample = map[string]interface{}{
			"total":               m.Total,
			"flow":                m.Flow,
			"battery":             m.Battery,
			"pressure":            m.Pressure,
			"temperature":         m.Temperature,
			"magnetic_tamper":     m.MagneticTamper,
			"rssi_raw":            m.RSSIRaw,
			"serial":              m.Serial,
			"valve":               m.Valve,
			"firmware":            m.Firmware,
			"network_status":      m.NetworkStatus,
			"rtc":                 m.RTC,
			"extended_status_1a":  m.ExtendedStatus1A,
			"model":               m.Model,
			"meter_index_20":      m.MeterIndex20,
			"counters":            m.Counters,
			"ext_block_12":        m.ExtBlock12,
			"timestamp_1f":        m.Timestamp1F,
		}

		list = append(list, m)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

