package qmc

// Credentials are the local QQ Music login values needed to request a
// per-file ekey from the official GetEVkey endpoint.
type Credentials struct {
	Uin       string
	Authst    string
	LoginType string
}
