import type { SDJWT, VCSDJWT } from '../sdjwt';

/** Image reference with required URI. */
export interface UriRef {
  uri: string;
}

export type ProofType = {
  type: string;
  jwks_uri: string;
};

/** Background definition from schema: either a color or an image URI. */
export type Background =
  | {
      color: string;
      image?: never;
    }
  | {
      image: UriRef;
      color?: never;
    };

export type KeyTarget =
  | 'credential'
  | 'credential_schema'
  | 'entity_configuration'
  | 'wallet_configuration'
  | 'credential_sd_claim';

export interface KeySelector {
  key: string;
  key_target: KeyTarget;
}

export interface PartsSelector {
  parts: ValuePart[];
}

export interface ComputedKeySelector {
  key: string;
  key_target: KeyTarget;
  compute: 'document_status';
}

export type ValueSelector = KeySelector | PartsSelector | ComputedKeySelector;

export type ValuePart =
  | {
      key: string;
      key_target: KeyTarget;
      join?: string;
    }
  | {
      literal: string;
    };

export interface Presentation {
  format?: 'date' | 'text' | 'url' | 'phn' | 'email';
  date_format?:
    | 'iso-8601'
    | 'yyyy-mm-dd'
    | 'yyyy-mm'
    | 'mm-dd-yyyy'
    | 'dd-mm-yyyy'
    | 'long'
    | 'medium'
    | 'short'
    | 'epoch';
  bg_color?: string;
  text_color?: string;
}

export interface FieldDefinition {
  label: string;
  value: ValueSelector | string;
  display_value?: ValueSelector | string;
  presentation?: Presentation;
}

export interface FieldRef {
  field_ref: string;
  label: string;
}

export type Field = FieldDefinition | FieldRef;

export interface SDField {
  field_ref: string;
  label: string;
}

export interface DisclosureGroup {
  id: string;
  title: string;
  subtext?: string;
  icon?: UriRef;
  sd_fields: SDField[];
}

export interface CardDetailsView {
  title?: string | null;
  fields?: Field[];
}

export interface CardDisclosuresView {
  title?: string;
  subtitle?: string | null;
  disclosure_groups?: DisclosureGroup[];
}

export interface Barcode {
  format: 'QRCode40';
  keybinding?: boolean;
}

export interface CredentialDisplayDefinition {
  $schema: string;
  $id: string;
  display_template: string;
  schema_uri: string;
  card_title: string;
  text_color: string;
  top_left_icon: UriRef;
  background: Background;

  top_right_image?: UriRef;
  bottom_right_image?: UriRef;
  primary_field: Field;
  secondary_field1?: Field;
  secondary_field2?: Field;
  secondary_field3?: Field;
  barcode?: Barcode;
  card_overview: CardOverview;
  card_details_view: CardDetailsView;
  card_disclosures_view: CardDisclosuresView;
  field_definitions: Record<string, FieldDefinition>;
}

export interface CredentialConfiguration {
  typ: string;
  description: string;
  credential_issuer: string;
  jwks_uri: string;
  revocation_list_endpoint: string;
  revocation_method: string;
  credential_definition: UriRef;
  credential_display: UriRef;
  proof_type: ProofType;
  icon?: UriRef;
}

export interface AlbertaCredentialIssuer {
  organization_name: string;
  organization_uri: string;
  description: string;
  information_uri: string;
  credential_configurations_supported: Record<string, CredentialConfiguration>;
  issuer_tz?: string;
}

export interface CardOverviewSectionEntry {
  label: string;
  link?: string;
}

export interface CardOverviewSection {
  title: string;
  entries: CardOverviewSectionEntry[];
}

export interface CardOverviewCardImage {
  uri: string;
  alt_text?: string;
}

export interface CardOverviewSampleContentImage {
  sample_content_json: string;
  alt_text?: string;
}

export interface CardOverview {
  title?: string;
  subtitle?: string | null;
  card_image?: CardOverviewCardImage | CardOverviewSampleContentImage;
  sections?: CardOverviewSection[];
}

/** Credential definition conforming to an SD-JWT v1 schema URI. */
interface SdJwtCredentialDefinition extends SDJWT {
  $schema: `${string}/sd-jwt-v1.json`;
}

/** Credential definition conforming to a VC+SD-JWT v1 schema URI. */
interface VcSdJwtCredentialDefinition extends VCSDJWT {
  $schema: `${string}/vc+sd-jwt-v1.json`;
}

/** A credential definition extending either the SD-JWT v1 or VC+SD-JWT v1 base schema. */
export type CredentialDefinition = SdJwtCredentialDefinition | VcSdJwtCredentialDefinition;
