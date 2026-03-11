package detector

import "testing"

func TestIsDNNNamePrefixBased(t *testing.T) {
    tests := []struct {
        name     string
        expected bool
    }{
        // Valid DNN names
        {"nabandonaread", true},          // n + abandon + area + d
        {"freakoverse.nabandonaread", true}, // subdomain of DNN
        {"nabtaabove", false},            // n + abt... no valid BIP39 prefix
        {"nabandoncandya", true},         // n + abandon + candy + a
        {"nabandonzooa", true},           // n + abandon + zoo + a
        {"nwinterzooa", true},            // n + winter + zoo + a

        // Invalid - not enough chars
        {"google.com", false},
        {"netflix.com", false},
        {"nostr.io", false},

        // Invalid - doesn't start with n
        {"abandonaread", false},

        // Invalid - too short
        {"nabcde", false},

        // Valid with subdomains
        {"sub.nabandonzooa", true},

        // Spaces = search query
        {"n abandon area d", false},
    }

    for _, test := range tests {
        result := IsDNNName(test.name)
        if result != test.expected {
            t.Errorf("IsDNNName(%q) = %v, want %v", test.name, result, test.expected)
        } else {
            t.Logf("? IsDNNName(%q) = %v", test.name, result)
        }
    }
}
