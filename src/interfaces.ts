/**
 * Copyright 2020 Inrupt Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
 * Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

import { DatasetCore, Quad, NamedNode, BlankNode } from "rdf-js";

/**
 * Alias to indicate where we expect to be given a URL represented as an RDF/JS NamedNode.
 */
export type Url = NamedNode;
/** @hidden Alias of Url for those who prefer to use IRI terminology. */
export type Iri = Url;
/**
 * Alias to indicate where we expect to be given a URL.
 */
export type UrlString = string;
/** @hidden Alias of UrlString for those who prefer to use IRI terminology. */
export type IriString = UrlString;
/**
 * Alias to indicate where we expect to be given a WebId.
 */
export type WebId = UrlString;

/**
 * A LitDataset represents all Quads from a single Resource.
 */
export type LitDataset = DatasetCore;
/**
 * A Thing represents all Quads with a given Subject URL and a given Named
 * Graph, from a single Resource.
 */
export type Thing = DatasetCore &
  ({ internal_url: UrlString } | { internal_localSubject: LocalNode });
/**
 * A [[Thing]] for which we know what the full Subject URL is.
 */
export type ThingPersisted = Thing & { internal_url: UrlString };
/**
 * A [[Thing]] whose full Subject URL will be determined when it is persisted.
 */
export type ThingLocal = Thing & { internal_localSubject: LocalNode };
/**
 * Represents the BlankNode that will be initialised to a NamedNode when persisted.
 *
 * This is a Blank Node with a `name` property attached, which will be used to construct this
 * Node's full URL once it is persisted, where it will transform into a Named Node.
 *
 * @hidden Utility type; library users should not need to interact with LocalNodes directly.
 */
export type LocalNode = BlankNode & { internal_name: string };

/**
 * A [[LitDataset]] containing Access Control rules for another LitDataset.
 *
 * Please note that the Web Access Control specification is not yet finalised, and hence, this
 * function is still experimental and can change in a non-major release.
 */
export type AclDataset = LitDataset &
  WithResourceInfo & { internal_accessTo: UrlString };

/**
 * @hidden Developers shouldn't need to directly access ACL rules. Instead, we provide our own functions that verify what access someone has.
 */
export type AclRule = Thing;

/**
 * An object with the boolean properties `read`, `append`, `write` and `control`, representing the
 * respective Access Modes defined by the Web Access Control specification.
 *
 * Since that specification is not finalised yet, this interface is still experimental.
 */
export type Access =
  // If someone has write permissions, they also have append permissions:
  {
    read: boolean;
    append: boolean;
    write: boolean;
    control: boolean;
  };

type internal_WacAllow = {
  user: Access;
  public: Access;
};

/**
 * [[LitDataset]]s fetched by solid-client include this metadata describing its relation to a Pod Resource.
 */
export type WithResourceInfo = {
  internal_resourceInfo: {
    fetchedFrom: UrlString;
    isLitDataset: boolean;
    contentType?: string;
    /**
     * The URL reported by the server as possibly containing an ACL file. Note that this file might
     * not necessarily exist, in which case the ACL of the nearest Container with an ACL applies.
     *
     * @ignore We anticipate the Solid spec to change how the ACL gets accessed, which would result
     *         in this API changing as well.
     */
    aclUrl?: UrlString;
    /**
     * Access permissions for the current user and the general public for this resource.
     *
     * @ignore There is no consensus yet about how this functionality will be incorporated in the
     *         final spec, so the final implementation might influence this API in the future.
     * @see https://github.com/solid/solid-spec/blob/cb1373a369398d561b909009bd0e5a8c3fec953b/api-rest.md#wac-allow-headers
     * @see https://github.com/solid/specification/issues/171
     */
    permissions?: internal_WacAllow;
  };
};

/**
 * @hidden Data structure to keep track of operations done by us; should not be read or manipulated by the developer.
 */
export type WithChangeLog = {
  internal_changeLog: {
    additions: Quad[];
    deletions: Quad[];
  };
};

/**
 * Please note that the Web Access Control specification is not yet finalised, and hence, this
 * function is still experimental and can change in a non-major release.
 *
 * @hidden Developers should use [[getResourceAcl]] and [[getFallbackAcl]] to access these.
 */
export type WithAcl = {
  internal_acl: {
    resourceAcl: AclDataset | null;
    fallbackAcl: AclDataset | null;
  };
};

/**
 * If this type applies to a Resource, an Access Control List that applies to it exists and is accessible to the currently authenticated user.
 *
 * Please note that the Web Access Control specification is not yet finalised, and hence, this
 * function is still experimental and can change in a non-major release.
 */
export type WithResourceAcl<Resource extends WithAcl = WithAcl> = Resource & {
  internal_acl: {
    resourceAcl: Exclude<WithAcl["internal_acl"]["resourceAcl"], null>;
  };
};

/**
 * If this type applies to a Resource, the Access Control List that applies to its nearest Container with an ACL is accessible to the currently authenticated user.
 *
 * Please note that the Web Access Control specification is not yet finalised, and hence, this
 * function is still experimental and can change in a non-major release.
 */
export type WithFallbackAcl<Resource extends WithAcl = WithAcl> = Resource & {
  internal_acl: {
    fallbackAcl: Exclude<WithAcl["internal_acl"]["fallbackAcl"], null>;
  };
};

/** @internal */
export function internal_toIriString(iri: Iri | IriString): IriString {
  return typeof iri === "string" ? iri : iri.value;
}

/**
 * Verify whether a given LitDataset includes metadata about where it was retrieved from.
 *
 * @param dataset A [[LitDataset]] that may have metadata attached about the Resource it was retrieved from.
 * @returns True if `dataset` includes metadata about the Resource it was retrieved from, false if not.
 */
export function hasResourceInfo<T extends LitDataset>(
  dataset: T
): dataset is T & WithResourceInfo {
  const potentialResourceInfo = dataset as T & WithResourceInfo;
  return typeof potentialResourceInfo.internal_resourceInfo === "object";
}

/** @internal */
export function hasChangelog<T extends LitDataset>(
  dataset: T
): dataset is T & WithChangeLog {
  const potentialChangeLog = dataset as T & WithChangeLog;
  return (
    typeof potentialChangeLog.internal_changeLog === "object" &&
    Array.isArray(potentialChangeLog.internal_changeLog.additions) &&
    Array.isArray(potentialChangeLog.internal_changeLog.deletions)
  );
}

/**
 * Verify whether a given LitDataset was fetched together with its Access Control List.
 *
 * Please note that the Web Access Control specification is not yet finalised, and hence, this
 * function is still experimental and can change in a non-major release.
 *
 * @param dataset A [[LitDataset]] that may have its ACLs attached.
 * @returns True if `dataset` was fetched together with its ACLs.
 */
export function hasAcl<T extends object>(dataset: T): dataset is T & WithAcl {
  const potentialAcl = dataset as T & WithAcl;
  return typeof potentialAcl.internal_acl === "object";
}

/**
 * If this type applies to a Resource, its Access Control List, if it exists, is accessible to the currently authenticated user.
 *
 * Please note that the Web Access Control specification is not yet finalised, and hence, this
 * function is still experimental and can change in a non-major release.
 */
export type WithAccessibleAcl<
  Resource extends WithResourceInfo = WithResourceInfo
> = Resource & {
  internal_resourceInfo: {
    aclUrl: Exclude<
      WithResourceInfo["internal_resourceInfo"]["aclUrl"],
      undefined
    >;
  };
};

/**
 * Given a [[LitDataset]], verify whether its Access Control List is accessible to the current user.
 *
 * This should generally only be true for LitDatasets fetched by
 * [[fetchLitDatasetWithAcl]].
 *
 * Please note that the Web Access Control specification is not yet finalised, and hence, this
 * function is still experimental and can change in a non-major release.
 *
 * @param dataset A [[LitDataset]].
 * @returns Whether the given `dataset` has a an ACL that is accessible to the current user.
 */
export function hasAccessibleAcl<Resource extends WithResourceInfo>(
  dataset: Resource
): dataset is WithAccessibleAcl<Resource> {
  return typeof dataset.internal_resourceInfo.aclUrl === "string";
}

/**
 * A RequestInit restriction where the method is set by the library
 *
 * Please note that this function is still experimental and can change in a non-major release.
 */
export type UploadRequestInit = Omit<RequestInit, "method">;
