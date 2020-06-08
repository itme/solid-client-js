import { DatasetCore, Quad, NamedNode, BlankNode } from "rdf-js";

/**
 * Alias to indicate where we expect an IRI.
 */
export type Iri = NamedNode;
export type IriString = string;
export type WebId = IriString;

/**
 * A LitDataset represents all Quads from a single Resource.
 */
export type LitDataset = DatasetCore;
/**
 * A Thing represents all Quads with a given Subject IRI and a given Named
 * Graph, from a single Resource.
 */
export type Thing = DatasetCore & ({ iri: IriString } | { name: string });
/**
 * A [[Thing]] for which we know what the full Subject IRI is.
 */
export type ThingPersisted = Thing & { iri: IriString };
/**
 * A [[Thing]] whose full Subject IRI will be determined when it is persisted.
 */
export type ThingLocal = Thing & { name: string };
/**
 * Represents the BlankNode that will be initialised to a NamedNode when persisted.
 *
 * This is a Blank Node with a `name` property attached, which will be used to construct this
 * Node's full IRI once it is persisted, where it will transform into a Named Node.
 */
export type LocalNode = BlankNode & { name: string };

export type unstable_AclDataset = LitDataset &
  DatasetInfo & { accessTo: IriString };

/**
 * @hidden Developers shouldn't need to directly access ACL rules. Instead, we provide our own functions that verify what access someone has.
 */
export type unstable_AclRule = Thing;

/**
 * An object with the boolean properties `read`, `append`, `write` and `control`, representing the
 * respective Access Modes defined by the Web Access Control specification.
 *
 * Since that specification is not finalised yet, this interface is still experimental.
 */
export type unstable_AccessModes =
  // If someone has write permissions, they also have append permissions:
  | {
      read: boolean;
      append: true;
      write: true;
      control: boolean;
    }
  | {
      read: boolean;
      append: boolean;
      write: false;
      control: boolean;
    };

type unstable_WacAllow = {
  user: unstable_AccessModes;
  public: unstable_AccessModes;
};
export type DatasetInfo = {
  datasetInfo: {
    fetchedFrom: IriString;
    /**
     * The IRI reported by the server as possibly containing an ACL file. Note that this file might
     * not necessarily exist, in which case the ACL of the nearest Container with an ACL applies.
     *
     * @ignore We anticipate the Solid spec to change how the ACL gets accessed, which would result
     *         in this API changing as well.
     */
    unstable_aclIri?: IriString;
    /**
     * Access permissions for the current user and the general public for this resource.
     *
     * @ignore There is no consensus yet about how this functionality will be incorporated in the
     *         final spec, so the final implementation might influence this API in the future.
     * @see https://github.com/solid/solid-spec/blob/cb1373a369398d561b909009bd0e5a8c3fec953b/api-rest.md#wac-allow-headers
     * @see https://github.com/solid/specification/issues/171
     */
    unstable_permissions?: unstable_WacAllow;
  };
};

export type ChangeLog = {
  changeLog: {
    additions: Quad[];
    deletions: Quad[];
  };
};

/**
 * @hidden Developers should use [[unstable_getResourceAcl]] and [[unstable_getFallbackAcl]] to access these.
 */
export type unstable_Acl = {
  acl: {
    resourceAcl?: unstable_AclDataset;
    fallbackAcl: unstable_AclDataset | null;
  };
};

export function hasDatasetInfo<T extends LitDataset>(
  dataset: T
): dataset is T & DatasetInfo {
  const potentialDatasetInfo = dataset as T & DatasetInfo;
  return typeof potentialDatasetInfo.datasetInfo === "object";
}

export function hasChangelog<T extends LitDataset>(
  dataset: T
): dataset is T & ChangeLog {
  const potentialChangeLog = dataset as T & ChangeLog;
  return (
    typeof potentialChangeLog.changeLog === "object" &&
    Array.isArray(potentialChangeLog.changeLog.additions) &&
    Array.isArray(potentialChangeLog.changeLog.deletions)
  );
}

/**
 * Given a [[LitDataset]], verify whether it has ACL data attached to it.
 *
 * This should generally only be true for LitDatasets fetched by
 * [[unstable_fetchLitDatasetWithAcl]].
 *
 * @param dataset A [[LitDataset]].
 * @returns Whether the given `dataset` has ACL data attached to it.
 * @internal
 */
export function unstable_hasAccessibleAcl<Dataset extends DatasetInfo>(
  dataset: Dataset
): dataset is Dataset & {
  datasetInfo: { unstable_aclIri: IriString };
} {
  return typeof dataset.datasetInfo.unstable_aclIri === "string";
}