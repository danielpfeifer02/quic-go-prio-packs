package packet_setting

var (
	ALLOW_SETTING_PN               bool                     = false
	OMIT_CONN_ID_RETIREMENT        bool                     = false
	ConnectionRetirementBPFHandler func(id []byte, l uint8) = nil
	ConnectionInitiationBPFHandler func(id []byte, l uint8) = nil
)
