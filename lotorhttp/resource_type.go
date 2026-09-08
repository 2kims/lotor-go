package lotorhttp

// ResourceTypeDefinition declares the application-owned graph and payload policy.
type ResourceTypeDefinition struct {
	ResourceType       string                    `json:"resource_type"`
	Kind               string                    `json:"kind"`
	Lifecycle          string                    `json:"lifecycle"`
	KeyBehavior        string                    `json:"key_behavior"`
	AllowedParentTypes []string                  `json:"allowed_parent_types"`
	Relations          []string                  `json:"relations"`
	InheritedRelations []string                  `json:"inherited_relations,omitempty"`
	CatalogEntryKinds  []string                  `json:"catalog_entry_kinds,omitempty"`
	Payload            ResourcePayloadTypePolicy `json:"payload"`
	DirectLinks        bool                      `json:"direct_links"`
	MayActAsPrincipal  bool                      `json:"may_act_as_principal,omitempty"`
	MayActAsSubjectSet bool                      `json:"may_act_as_subject_set,omitempty"`
}

type ResourcePayloadTypePolicy struct {
	Storage string                      `json:"storage"`
	Slots   []ResourcePayloadSlotPolicy `json:"slots"`
}

type ResourcePayloadSlotPolicy struct {
	Name              string   `json:"name"`
	SchemaIDs         []string `json:"schema_ids"`
	MaximumObjectSize int64    `json:"maximum_object_size"`
	Required          bool     `json:"required"`
}
