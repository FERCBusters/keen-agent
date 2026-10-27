package nativeposture

// Byte offsets in SYSTEM_POWER_CAPABILITIES (winnt.h), whose BOOLEAN members
// are one byte each: SystemS1-S3 at 3-5, AoAc (Modern Standby) at 20 and
// SystemBatteriesPresent at 30. The structure is 76 bytes.
const (
	powerCapsSize           = 76
	powerCapsSystemS1       = 3
	powerCapsSystemS3       = 5
	powerCapsAoAc           = 20
	powerCapsBatteryPresent = 30
)

// powerCapabilitiesPrelude turns the structure into a fixed PowerShell
// assignment. Only literal booleans reach the script.
func powerCapabilitiesPrelude(caps []byte) string {
	if len(caps) < powerCapsSize {
		return ""
	}
	flag := func(set bool) string {
		if set {
			return "$true"
		}
		return "$false"
	}
	sleep := false
	for _, b := range caps[powerCapsSystemS1 : powerCapsSystemS3+1] {
		sleep = sleep || b != 0
	}
	return "$keenPowerCapabilities = @{ sleep_supported=" + flag(sleep) +
		"; modern_standby=" + flag(caps[powerCapsAoAc] != 0) +
		"; batteries_present=" + flag(caps[powerCapsBatteryPresent] != 0) + " }\n"
}
