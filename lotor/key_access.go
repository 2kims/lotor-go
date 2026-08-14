package lotor

// SubjectKeyRegistration contains client-generated device public keys and an optional opaque,
// passphrase-protected private-key backup. Passphrases and plaintext private keys must never be
// placed in this structure.
type SubjectKeyRegistration struct {
	Actor                     string
	Subject                   string
	KeyID                     string
	DeviceID                  string
	EncryptionAlgorithm       string
	EncryptionPublicKey       []byte
	SigningAlgorithm          string
	SigningPublicKey          []byte
	EncryptedPrivateKeyBackup []byte
	BackupKDF                 string
	BackupSalt                []byte
	BackupNonce               []byte
	BackupFormatVersion       uint64
	Proof                     []byte
}

type SubjectKeyMutation struct {
	Accepted bool
	Reason   string
	KeyID    string
	LogSeq   uint64
}

type SubjectKey struct {
	KeyID                     string
	DeviceID                  string
	EncryptionAlgorithm       string
	EncryptionPublicKey       []byte
	SigningAlgorithm          string
	SigningPublicKey          []byte
	EncryptedPrivateKeyBackup []byte
	BackupKDF                 string
	BackupSalt                []byte
	BackupNonce               []byte
	Status                    string
	BackupFormatVersion       uint64
	LogSeq                    uint64
}

func (c *Client) SubjectKeyRegister(input SubjectKeyRegistration) (SubjectKeyMutation, error) {
	values, err := c.do(opSUBJECTKEYREGISTER, []value{
		vAddr(input.Actor), vAddr(input.Subject), vStr(input.KeyID), vStr(input.DeviceID),
		vStr(input.EncryptionAlgorithm), vBytes(input.EncryptionPublicKey),
		vStr(input.SigningAlgorithm), vBytes(input.SigningPublicKey),
		vBytes(input.EncryptedPrivateKeyBackup), vStr(input.BackupKDF),
		vBytes(input.BackupSalt), vBytes(input.BackupNonce), vU64(input.BackupFormatVersion),
		vBytes(input.Proof),
	})
	if err != nil {
		return SubjectKeyMutation{}, err
	}
	return decodeSubjectKeyMutation(values), nil
}

func (c *Client) SubjectKeyRevoke(actor, subject, keyID string) (SubjectKeyMutation, error) {
	values, err := c.do(opSUBJECTKEYREVOKE, []value{vAddr(actor), vAddr(subject), vStr(keyID)})
	if err != nil {
		return SubjectKeyMutation{}, err
	}
	return decodeSubjectKeyMutation(values), nil
}

func (c *Client) SubjectKeyList(actor, subject string) ([]SubjectKey, error) {
	values, err := c.do(opSUBJECTKEYLIST, []value{vAddr(actor), vAddr(subject)})
	if err != nil {
		return nil, err
	}
	if len(values) < 3 || !values[0].asBool() || values[2].Kind != tagList {
		return []SubjectKey{}, nil
	}
	result := make([]SubjectKey, 0, len(values[2].List))
	for _, item := range values[2].List {
		if item.Kind != tagMap {
			continue
		}
		result = append(result, SubjectKey{
			KeyID: item.Map["key_id"].asStr(), DeviceID: item.Map["device_id"].asStr(),
			EncryptionAlgorithm:       item.Map["encryption_algorithm"].asStr(),
			EncryptionPublicKey:       append([]byte(nil), item.Map["encryption_public_key"].Bytes...),
			SigningAlgorithm:          item.Map["signing_algorithm"].asStr(),
			SigningPublicKey:          append([]byte(nil), item.Map["signing_public_key"].Bytes...),
			EncryptedPrivateKeyBackup: append([]byte(nil), item.Map["encrypted_private_key_backup"].Bytes...),
			BackupKDF:                 item.Map["backup_kdf"].asStr(),
			BackupSalt:                append([]byte(nil), item.Map["backup_salt"].Bytes...),
			BackupNonce:               append([]byte(nil), item.Map["backup_nonce"].Bytes...),
			BackupFormatVersion:       item.Map["backup_format_version"].U64,
			Status:                    item.Map["status"].asStr(), LogSeq: item.Map["log_seq"].U64,
		})
	}
	return result, nil
}

func decodeSubjectKeyMutation(values []value) SubjectKeyMutation {
	result := SubjectKeyMutation{}
	if len(values) > 0 {
		result.Accepted = values[0].asBool()
	}
	if len(values) > 1 {
		result.Reason = values[1].asStr()
	}
	if len(values) > 2 {
		result.KeyID = values[2].asStr()
	}
	if len(values) > 3 {
		result.LogSeq = values[3].U64
	}
	return result
}

type ResourceKeyVersionInput struct {
	Scope, Actor, KeyResource, Algorithm string
	Version                              uint64
}

type ResourceGrantInput struct {
	Actor, GrantID, Scope, Resource, Subject, Relation string
	KeyResource, RecipientKeyID, InvitationID          string
	KeyVersion                                         uint64
}

type ResourceEnvelopeInput struct {
	Scope, Actor, GrantID, KeyResource, RecipientSubject string
	RecipientKeyID, EncryptionSuite, Issuer, IssuerKeyID string
	KeyVersion                                           uint64
	Ciphertext, AADHash, Signature                       []byte
}

type ResourceGrantMutation struct {
	Accepted                bool
	Reason, GrantID, Status string
	LogSeq                  uint64
}

type ResourceMember struct {
	GrantID, Subject, Relation, Resource, KeyResource string
	RecipientKeyID, InvitationID, Status              string
	KeyVersion, LogSeq                                uint64
	RecipientKeyStatus, RecipientEncryptionAlgorithm  string
	RecipientEncryptionPublicKey                      []byte
	RecipientSigningAlgorithm                         string
	RecipientSigningPublicKey                         []byte
}

type ResourceEnvelope struct {
	GrantID, KeyResource, RecipientKeyID, EncryptionSuite, Issuer string
	IssuerKeyID                                                   string
	KeyVersion, LogSeq                                            uint64
	Ciphertext, AADHash, Signature                                []byte
	Scope, Resource, RecipientSubject, Relation                   string
}

func (c *Client) ResourceKeyVersionCreate(input ResourceKeyVersionInput) (SubjectKeyMutation, error) {
	values, err := c.do(opRESOURCEKEYCREATE, []value{vAddr(input.Scope), vAddr(input.Actor), vAddr(input.KeyResource), vU64(input.Version), vStr(input.Algorithm)})
	if err != nil {
		return SubjectKeyMutation{}, err
	}
	result := SubjectKeyMutation{}
	if len(values) > 0 {
		result.Accepted = values[0].asBool()
	}
	if len(values) > 1 {
		result.Reason = values[1].asStr()
	}
	if len(values) > 2 {
		result.KeyID = values[2].asStr()
	}
	if len(values) > 4 {
		result.LogSeq = values[4].U64
	}
	return result, nil
}

func (c *Client) ResourceGrantPrepare(input ResourceGrantInput) (ResourceGrantMutation, error) {
	values, err := c.do(opRESOURCEGRANTPREPARE, []value{
		vAddr(input.Actor), vStr(input.GrantID), vAddr(input.Scope), vAddr(input.Resource),
		vAddr(input.Subject), vStr(input.Relation), vAddr(input.KeyResource), vU64(input.KeyVersion),
		vStr(input.RecipientKeyID), vStr(input.InvitationID),
	})
	if err != nil {
		return ResourceGrantMutation{}, err
	}
	return decodeResourceGrantMutation(values), nil
}

func (c *Client) ResourceEnvelopeSubmit(input ResourceEnvelopeInput) (ResourceGrantMutation, error) {
	values, err := c.do(opRESOURCEENVELOPESUBMIT, []value{
		vAddr(input.Scope), vAddr(input.Actor), vStr(input.GrantID), vAddr(input.KeyResource),
		vU64(input.KeyVersion), vAddr(input.RecipientSubject), vStr(input.RecipientKeyID),
		vStr(input.EncryptionSuite), vBytes(input.Ciphertext), vBytes(input.AADHash),
		vAddr(input.Issuer), vStr(input.IssuerKeyID), vBytes(input.Signature),
	})
	if err != nil {
		return ResourceGrantMutation{}, err
	}
	return decodeResourceGrantMutation(values), nil
}

func (c *Client) ResourceEnvelopeGetSelf(actor, subject, resource string) (ResourceEnvelope, bool, error) {
	values, err := c.do(opRESOURCEENVELOPEGET, []value{vAddr(actor), vAddr(subject), vAddr(resource)})
	if err != nil {
		return ResourceEnvelope{}, false, err
	}
	if len(values) < 3 || !values[0].asBool() || values[2].Kind != tagMap {
		return ResourceEnvelope{}, false, nil
	}
	item := values[2].Map
	return ResourceEnvelope{
		GrantID: item["grant_id"].asStr(), KeyResource: item["key_resource"].asStr(),
		KeyVersion: item["key_version"].U64, RecipientKeyID: item["recipient_key_id"].asStr(),
		EncryptionSuite: item["encryption_suite"].asStr(), Ciphertext: append([]byte(nil), item["ciphertext"].Bytes...),
		AADHash: append([]byte(nil), item["aad_hash"].Bytes...), Issuer: item["issuer"].asStr(),
		IssuerKeyID: item["issuer_key_id"].asStr(),
		Signature:   append([]byte(nil), item["signature"].Bytes...), LogSeq: item["log_seq"].U64,
		Scope: item["scope"].asStr(), Resource: item["resource"].asStr(),
		RecipientSubject: item["recipient_subject"].asStr(), Relation: item["relation"].asStr(),
	}, true, nil
}

func (c *Client) ResourceMemberList(scope, actor, resource string) ([]ResourceMember, error) {
	values, err := c.do(opRESOURCEMEMBERLIST, []value{vAddr(scope), vAddr(actor), vAddr(resource)})
	if err != nil {
		return nil, err
	}
	if len(values) < 3 || !values[0].asBool() || values[2].Kind != tagList {
		return []ResourceMember{}, nil
	}
	result := make([]ResourceMember, 0, len(values[2].List))
	for _, entry := range values[2].List {
		if entry.Kind != tagMap {
			continue
		}
		item := entry.Map
		result = append(result, ResourceMember{
			GrantID: item["grant_id"].asStr(), Subject: item["subject"].asStr(), Relation: item["relation"].asStr(),
			Resource: item["resource"].asStr(), KeyResource: item["key_resource"].asStr(), KeyVersion: item["key_version"].U64,
			RecipientKeyID: item["recipient_key_id"].asStr(), InvitationID: item["invitation_id"].asStr(),
			Status: item["status"].asStr(), LogSeq: item["log_seq"].U64,
			RecipientKeyStatus:           item["recipient_key_status"].asStr(),
			RecipientEncryptionAlgorithm: item["recipient_encryption_algorithm"].asStr(),
			RecipientEncryptionPublicKey: append([]byte(nil), item["recipient_encryption_public_key"].Bytes...),
			RecipientSigningAlgorithm:    item["recipient_signing_algorithm"].asStr(),
			RecipientSigningPublicKey:    append([]byte(nil), item["recipient_signing_public_key"].Bytes...),
		})
	}
	return result, nil
}

func (c *Client) ResourceGrantRevoke(scope, actor, grantID string) (ResourceGrantMutation, error) {
	values, err := c.do(opRESOURCEGRANTREVOKE, []value{vAddr(scope), vAddr(actor), vStr(grantID)})
	if err != nil {
		return ResourceGrantMutation{}, err
	}
	return decodeResourceGrantMutation(values), nil
}

func decodeResourceGrantMutation(values []value) ResourceGrantMutation {
	result := ResourceGrantMutation{}
	if len(values) > 0 {
		result.Accepted = values[0].asBool()
	}
	if len(values) > 1 {
		result.Reason = values[1].asStr()
	}
	if len(values) > 2 {
		result.GrantID = values[2].asStr()
	}
	if len(values) > 3 {
		result.Status = values[3].asStr()
	}
	if len(values) > 4 {
		result.LogSeq = values[4].U64
	}
	return result
}
