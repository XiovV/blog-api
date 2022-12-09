package server

func (s *Server) encryptMfaSecret(secret []byte) []byte {
	nonce := make([]byte, s.gcm.NonceSize())
	return s.gcm.Seal(nonce, nonce, secret, nil)
}

func (s *Server) decryptMfaSecret(encryptedSecret []byte) ([]byte, error) {
	nonceSize := s.gcm.NonceSize()
	nonce, cipherText := encryptedSecret[:nonceSize], encryptedSecret[nonceSize:]
	return s.gcm.Open(nil, nonce, cipherText, nil)
}
