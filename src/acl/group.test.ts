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

import { dataset } from "@rdfjs/dataset";
import {
  LitDataset,
  WithResourceInfo,
  IriString,
  unstable_Access,
  unstable_AclDataset,
  unstable_WithAcl,
  WebId,
} from "../interfaces";
import { DataFactory } from "../rdfjs";
import {
  unstable_getGroupDefaultAccessOne,
  unstable_getGroupResourceAccessOne,
  unstable_getGroupResourceAccessAll,
  unstable_getGroupDefaultAccessAll,
  unstable_getGroupAccessOne,
  unstable_getGroupAccessAll,
} from "./group";

function addAclRuleQuads(
  aclDataset: LitDataset & WithResourceInfo,
  group: IriString,
  resource: IriString,
  access: unstable_Access,
  type: "resource" | "default"
): unstable_AclDataset {
  const subjectIri = resource + "#" + encodeURIComponent(group) + Math.random();
  aclDataset.add(
    DataFactory.quad(
      DataFactory.namedNode(subjectIri),
      DataFactory.namedNode("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"),
      DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Authorization")
    )
  );
  aclDataset.add(
    DataFactory.quad(
      DataFactory.namedNode(subjectIri),
      DataFactory.namedNode(
        type === "resource"
          ? "http://www.w3.org/ns/auth/acl#accessTo"
          : "http://www.w3.org/ns/auth/acl#default"
      ),
      DataFactory.namedNode(resource)
    )
  );
  aclDataset.add(
    DataFactory.quad(
      DataFactory.namedNode(subjectIri),
      DataFactory.namedNode("http://www.w3.org/ns/auth/acl#agentGroup"),
      DataFactory.namedNode(group)
    )
  );
  if (access.read) {
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#mode"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Read")
      )
    );
  }
  if (access.append) {
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#mode"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Append")
      )
    );
  }
  if (access.write) {
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#mode"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Write")
      )
    );
  }
  if (access.control) {
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#mode"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Control")
      )
    );
  }

  return Object.assign(aclDataset, { internal_accessTo: resource });
}

function addAclDatasetToLitDataset(
  litDataset: LitDataset & WithResourceInfo,
  aclDataset: unstable_AclDataset,
  type: "resource" | "fallback"
): LitDataset & WithResourceInfo & unstable_WithAcl {
  const acl: unstable_WithAcl["internal_acl"] = {
    fallbackAcl: null,
    resourceAcl: null,
    ...(((litDataset as any) as unstable_WithAcl).internal_acl ?? {}),
  };
  if (type === "resource") {
    litDataset.internal_resourceInfo.unstable_aclUrl =
      aclDataset.internal_resourceInfo.fetchedFrom;
    aclDataset.internal_accessTo = litDataset.internal_resourceInfo.fetchedFrom;
    acl.resourceAcl = aclDataset;
  } else if (type === "fallback") {
    acl.fallbackAcl = aclDataset;
  }
  return Object.assign(litDataset, { internal_acl: acl });
}

function getMockDataset(fetchedFrom: IriString): LitDataset & WithResourceInfo {
  return Object.assign(dataset(), {
    internal_resourceInfo: {
      fetchedFrom: fetchedFrom,
      isLitDataset: true,
    },
  });
}

describe("getGroupAccessOne", () => {
  it("returns the Resource's own applicable ACL rules", () => {
    const litDataset = getMockDataset("https://some.pod/container/resource");
    const resourceAcl = addAclRuleQuads(
      getMockDataset("https://some.pod/container/resource.acl"),
      "https://some.pod/group#id",
      "https://some.pod/container/resource",
      { read: false, append: false, write: false, control: true },
      "resource"
    );
    const litDatasetWithAcl = addAclDatasetToLitDataset(
      litDataset,
      resourceAcl,
      "resource"
    );

    const access = unstable_getGroupAccessOne(
      litDatasetWithAcl,
      "https://some.pod/group#id"
    );

    expect(access).toEqual({
      read: false,
      append: false,
      write: false,
      control: true,
    });
  });

  it("returns the fallback ACL rules if no Resource ACL LitDataset is available", () => {
    const litDataset = getMockDataset("https://some.pod/container/resource");
    const fallbackAcl = addAclRuleQuads(
      getMockDataset("https://some.pod/container/.acl"),
      "https://some.pod/group#id",
      "https://some.pod/container/",
      { read: false, append: false, write: false, control: true },
      "default"
    );
    const litDatasetWithAcl = addAclDatasetToLitDataset(
      litDataset,
      fallbackAcl,
      "fallback"
    );

    const access = unstable_getGroupAccessOne(
      litDatasetWithAcl,
      "https://some.pod/group#id"
    );

    expect(access).toEqual({
      read: false,
      append: false,
      write: false,
      control: true,
    });
  });

  it("returns null if neither the Resource's own nor a fallback ACL was accessible", () => {
    const litDataset = getMockDataset("https://some.pod/container/resource");
    const inaccessibleAcl: unstable_WithAcl = {
      internal_acl: { fallbackAcl: null, resourceAcl: null },
    };
    const litDatasetWithInaccessibleAcl = Object.assign(
      litDataset,
      inaccessibleAcl
    );

    expect(
      unstable_getGroupAccessOne(
        litDatasetWithInaccessibleAcl,
        "https://arbitrary.pod/profileDoc#webId"
      )
    ).toBeNull();
  });

  it("ignores the fallback ACL rules if a Resource ACL LitDataset is available", () => {
    const litDataset = getMockDataset("https://some.pod/container/resource");
    const resourceAcl = addAclRuleQuads(
      getMockDataset("https://some.pod/container/resource.acl"),
      "https://some.pod/group#id",
      "https://some.pod/container/resource",
      { read: true, append: false, write: false, control: false },
      "resource"
    );
    const fallbackAcl = addAclRuleQuads(
      getMockDataset("https://some.pod/container/.acl"),
      "https://some.pod/group#id",
      "https://some.pod/container/",
      { read: false, append: false, write: false, control: true },
      "default"
    );
    const litDatasetWithJustResourceAcl = addAclDatasetToLitDataset(
      litDataset,
      resourceAcl,
      "resource"
    );
    const litDatasetWithAcl = addAclDatasetToLitDataset(
      litDatasetWithJustResourceAcl,
      fallbackAcl,
      "fallback"
    );

    const access = unstable_getGroupAccessOne(
      litDatasetWithAcl,
      "https://some.pod/group#id"
    );

    expect(access).toEqual({
      read: true,
      append: false,
      write: false,
      control: false,
    });
  });

  it("ignores default ACL rules from the Resource's own ACL LitDataset", () => {
    const litDataset = getMockDataset("https://some.pod/container/");
    const resourceAcl = addAclRuleQuads(
      getMockDataset("https://some.pod/container/.acl"),
      "https://some.pod/group#id",
      "https://some.pod/container/",
      { read: true, append: false, write: false, control: false },
      "resource"
    );
    const resourceAclWithDefaultRules = addAclRuleQuads(
      resourceAcl,
      "https://some.pod/group#id",
      "https://some.pod/container/",
      { read: false, append: false, write: false, control: true },
      "default"
    );
    const litDatasetWithAcl = addAclDatasetToLitDataset(
      litDataset,
      resourceAclWithDefaultRules,
      "resource"
    );

    const access = unstable_getGroupAccessOne(
      litDatasetWithAcl,
      "https://some.pod/group#id"
    );

    expect(access).toEqual({
      read: true,
      append: false,
      write: false,
      control: false,
    });
  });

  it("ignores Resource ACL rules from the fallback ACL LitDataset", () => {
    const litDataset = getMockDataset("https://some.pod/container/resource");
    const fallbackAcl = addAclRuleQuads(
      getMockDataset("https://some.pod/container/.acl"),
      "https://some.pod/group#id",
      "https://some.pod/container/",
      { read: true, append: false, write: false, control: false },
      "resource"
    );
    const fallbackAclWithDefaultRules = addAclRuleQuads(
      fallbackAcl,
      "https://some.pod/group#id",
      "https://some.pod/container/",
      { read: false, append: false, write: false, control: true },
      "default"
    );
    const litDatasetWithAcl = addAclDatasetToLitDataset(
      litDataset,
      fallbackAclWithDefaultRules,
      "fallback"
    );

    const access = unstable_getGroupAccessOne(
      litDatasetWithAcl,
      "https://some.pod/group#id"
    );

    expect(access).toEqual({
      read: false,
      append: false,
      write: false,
      control: true,
    });
  });
});

describe("getGroupAccessAll", () => {
  it("returns the Resource's own applicable ACL rules, grouped by Group URL", () => {
    const litDataset = getMockDataset("https://some.pod/container/resource");
    const resourceAcl = addAclRuleQuads(
      getMockDataset("https://some.pod/container/resource.acl"),
      "https://some.pod/group#id",
      "https://some.pod/container/resource",
      { read: false, append: false, write: false, control: true },
      "resource"
    );
    const litDatasetWithAcl = addAclDatasetToLitDataset(
      litDataset,
      resourceAcl,
      "resource"
    );

    const access = unstable_getGroupAccessAll(litDatasetWithAcl);

    expect(access).toEqual({
      "https://some.pod/group#id": {
        read: false,
        append: false,
        write: false,
        control: true,
      },
    });
  });

  it("returns the fallback ACL rules if no Resource ACL LitDataset is available", () => {
    const litDataset = getMockDataset("https://some.pod/container/resource");
    const fallbackAcl = addAclRuleQuads(
      getMockDataset("https://some.pod/container/.acl"),
      "https://some.pod/group#id",
      "https://some.pod/container/",
      { read: false, append: false, write: false, control: true },
      "default"
    );
    const litDatasetWithAcl = addAclDatasetToLitDataset(
      litDataset,
      fallbackAcl,
      "fallback"
    );

    const access = unstable_getGroupAccessAll(litDatasetWithAcl);

    expect(access).toEqual({
      "https://some.pod/group#id": {
        read: false,
        append: false,
        write: false,
        control: true,
      },
    });
  });

  it("returns null if neither the Resource's own nor a fallback ACL was accessible", () => {
    const litDataset = getMockDataset("https://some.pod/container/resource");
    const inaccessibleAcl: unstable_WithAcl = {
      internal_acl: { fallbackAcl: null, resourceAcl: null },
    };
    const litDatasetWithInaccessibleAcl = Object.assign(
      litDataset,
      inaccessibleAcl
    );

    expect(
      unstable_getGroupAccessAll(litDatasetWithInaccessibleAcl)
    ).toBeNull();
  });

  it("ignores the fallback ACL rules if a Resource ACL LitDataset is available", () => {
    const litDataset = getMockDataset("https://some.pod/container/resource");
    const resourceAcl = addAclRuleQuads(
      getMockDataset("https://some.pod/container/resource.acl"),
      "https://some.pod/group#id",
      "https://some.pod/container/resource",
      { read: true, append: false, write: false, control: false },
      "resource"
    );
    const fallbackAcl = addAclRuleQuads(
      getMockDataset("https://some.pod/container/.acl"),
      "https://some.pod/group#id",
      "https://some.pod/container/",
      { read: false, append: false, write: false, control: true },
      "default"
    );
    const litDatasetWithJustResourceAcl = addAclDatasetToLitDataset(
      litDataset,
      resourceAcl,
      "resource"
    );
    const litDatasetWithAcl = addAclDatasetToLitDataset(
      litDatasetWithJustResourceAcl,
      fallbackAcl,
      "fallback"
    );

    const access = unstable_getGroupAccessAll(litDatasetWithAcl);

    expect(access).toEqual({
      "https://some.pod/group#id": {
        read: true,
        append: false,
        write: false,
        control: false,
      },
    });
  });

  it("does not merge fallback ACL rules with a Resource's own ACL rules, if available", () => {
    const litDataset = getMockDataset("https://some.pod/container/resource");
    const resourceAcl = addAclRuleQuads(
      getMockDataset("https://some.pod/container/resource.acl"),
      "https://some.pod/group#id",
      "https://some.pod/container/resource",
      { read: true, append: false, write: false, control: false },
      "resource"
    );
    const fallbackAcl = addAclRuleQuads(
      getMockDataset("https://some.pod/container/.acl"),
      "https://some-other.pod/profileDoc#webId",
      "https://some.pod/container/",
      { read: false, append: false, write: false, control: true },
      "default"
    );
    const litDatasetWithJustResourceAcl = addAclDatasetToLitDataset(
      litDataset,
      resourceAcl,
      "resource"
    );
    const litDatasetWithAcl = addAclDatasetToLitDataset(
      litDatasetWithJustResourceAcl,
      fallbackAcl,
      "fallback"
    );

    const access = unstable_getGroupAccessAll(litDatasetWithAcl);

    // It only includes rules for agent "https://some.pod/group#id",
    // not for "https://some-other.pod/profileDoc#webId"
    expect(access).toEqual({
      "https://some.pod/group#id": {
        read: true,
        append: false,
        write: false,
        control: false,
      },
    });
  });

  it("ignores default ACL rules from the Resource's own ACL LitDataset", () => {
    const litDataset = getMockDataset("https://some.pod/container/");
    const resourceAcl = addAclRuleQuads(
      getMockDataset("https://some.pod/container/.acl"),
      "https://some.pod/group#id",
      "https://some.pod/container/",
      { read: true, append: false, write: false, control: false },
      "resource"
    );
    const resourceAclWithDefaultRules = addAclRuleQuads(
      resourceAcl,
      "https://some.pod/group#id",
      "https://some.pod/container/",
      { read: false, append: false, write: false, control: true },
      "default"
    );
    const litDatasetWithAcl = addAclDatasetToLitDataset(
      litDataset,
      resourceAclWithDefaultRules,
      "resource"
    );

    const access = unstable_getGroupAccessAll(litDatasetWithAcl);

    expect(access).toEqual({
      "https://some.pod/group#id": {
        read: true,
        append: false,
        write: false,
        control: false,
      },
    });
  });

  it("ignores Resource ACL rules from the fallback ACL LitDataset", () => {
    const litDataset = getMockDataset("https://some.pod/container/resource");
    const fallbackAcl = addAclRuleQuads(
      getMockDataset("https://some.pod/container/.acl"),
      "https://some.pod/group#id",
      "https://some.pod/container/",
      { read: true, append: false, write: false, control: false },
      "resource"
    );
    const fallbackAclWithDefaultRules = addAclRuleQuads(
      fallbackAcl,
      "https://some.pod/group#id",
      "https://some.pod/container/",
      { read: false, append: false, write: false, control: true },
      "default"
    );
    const litDatasetWithAcl = addAclDatasetToLitDataset(
      litDataset,
      fallbackAclWithDefaultRules,
      "fallback"
    );

    const access = unstable_getGroupAccessAll(litDatasetWithAcl);

    expect(access).toEqual({
      "https://some.pod/group#id": {
        read: false,
        append: false,
        write: false,
        control: true,
      },
    });
  });
});

describe("getGroupResourceAccessOne", () => {
  it("returns the applicable Access Modes for a single Group", () => {
    const resourceAcl = addAclRuleQuads(
      getMockDataset("https://arbitrary.pod/resource.acl"),
      "https://some.pod/group#id",
      "https://arbitrary.pod/resource",
      { read: true, append: false, write: false, control: true },
      "resource"
    );

    const groupAccess = unstable_getGroupResourceAccessOne(
      resourceAcl,
      "https://some.pod/group#id"
    );

    expect(groupAccess).toEqual({
      read: true,
      append: false,
      write: false,
      control: true,
    });
  });

  it("combines Access Modes defined for a given Group in separate rules", () => {
    let resourceAcl = addAclRuleQuads(
      getMockDataset("https://arbitrary.pod/resource.acl"),
      "https://some.pod/group#id",
      "https://arbitrary.pod/resource",
      { read: true, append: false, write: false, control: false },
      "resource"
    );
    resourceAcl = addAclRuleQuads(
      resourceAcl,
      "https://some.pod/group#id",
      "https://arbitrary.pod/resource",
      { read: false, append: true, write: false, control: false },
      "resource"
    );

    const groupAccess = unstable_getGroupResourceAccessOne(
      resourceAcl,
      "https://some.pod/group#id"
    );

    expect(groupAccess).toEqual({
      read: true,
      append: true,
      write: false,
      control: false,
    });
  });

  it("returns false for all Access Modes if there are no ACL rules for the given Group", () => {
    const resourceAcl = addAclRuleQuads(
      getMockDataset("https://arbitrary.pod/resource.acl"),
      "https://some.pod/group#id",
      "https://arbitrary.pod/resource",
      { read: true, append: false, write: false, control: false },
      "resource"
    );

    const groupAccess = unstable_getGroupResourceAccessOne(
      resourceAcl,
      "https://some-other.pod/group#id"
    );

    expect(groupAccess).toEqual({
      read: false,
      append: false,
      write: false,
      control: false,
    });
  });

  it("ignores ACL rules that apply to a different Group", () => {
    let resourceAcl = addAclRuleQuads(
      getMockDataset("https://arbitrary.pod/resource.acl"),
      "https://some-other.pod/group#id",
      "https://arbitrary.pod/resource",
      { read: true, append: false, write: false, control: false },
      "resource"
    );
    resourceAcl = addAclRuleQuads(
      resourceAcl,
      "https://some.pod/group#id",
      "https://arbitrary.pod/resource",
      { read: false, append: true, write: false, control: false },
      "resource"
    );

    const groupAccess = unstable_getGroupResourceAccessOne(
      resourceAcl,
      "https://some.pod/group#id"
    );

    expect(groupAccess).toEqual({
      read: false,
      append: true,
      write: false,
      control: false,
    });
  });

  it("ignores ACL rules that apply to a different Resource", () => {
    let resourceAcl = addAclRuleQuads(
      getMockDataset("https://some.pod/resource.acl"),
      "https://arbitrary.pod/group#id",
      "https://some-other.pod/resource",
      { read: true, append: false, write: false, control: false },
      "resource"
    );
    resourceAcl = addAclRuleQuads(
      resourceAcl,
      "https://arbitrary.pod/group#id",
      "https://some.pod/resource",
      { read: false, append: true, write: false, control: false },
      "resource"
    );

    const groupAccess = unstable_getGroupResourceAccessOne(
      resourceAcl,
      "https://arbitrary.pod/group#id"
    );

    expect(groupAccess).toEqual({
      read: false,
      append: true,
      write: false,
      control: false,
    });
  });
});

describe("getGroupResourceAccessAll", () => {
  it("returns the applicable Access Modes for all Groups for whom Access Modes have been defined", () => {
    let resourceAcl = addAclRuleQuads(
      getMockDataset("https://arbitrary.pod/resource.acl"),
      "https://some-other.pod/group#id",
      "https://arbitrary.pod/resource",
      { read: true, append: false, write: false, control: false },
      "resource"
    );
    resourceAcl = addAclRuleQuads(
      resourceAcl,
      "https://some.pod/group#id",
      "https://arbitrary.pod/resource",
      { read: false, append: true, write: false, control: false },
      "resource"
    );

    const groupAccess = unstable_getGroupResourceAccessAll(resourceAcl);

    expect(groupAccess).toEqual({
      "https://some.pod/group#id": {
        read: false,
        append: true,
        write: false,
        control: false,
      },
      "https://some-other.pod/group#id": {
        read: true,
        append: false,
        write: false,
        control: false,
      },
    });
  });

  it("combines Access Modes defined for the same Groups in different Rules", () => {
    let resourceAcl = addAclRuleQuads(
      getMockDataset("https://arbitrary.pod/resource.acl"),
      "https://some.pod/group#id",
      "https://arbitrary.pod/resource",
      { read: true, append: false, write: false, control: false },
      "resource"
    );
    resourceAcl = addAclRuleQuads(
      resourceAcl,
      "https://some.pod/group#id",
      "https://arbitrary.pod/resource",
      { read: false, append: true, write: false, control: false },
      "resource"
    );

    const groupAccess = unstable_getGroupResourceAccessAll(resourceAcl);

    expect(groupAccess).toEqual({
      "https://some.pod/group#id": {
        read: true,
        append: true,
        write: false,
        control: false,
      },
    });
  });

  it("returns Access Modes for all Groups even if they are assigned in the same Rule", () => {
    const resourceAcl = addAclRuleQuads(
      getMockDataset("https://arbitrary.pod/resource.acl"),
      "https://some.pod/group#id",
      "https://arbitrary.pod/resource",
      { read: true, append: false, write: false, control: false },
      "resource"
    );
    const oneQuad = Array.from(resourceAcl)[0];
    resourceAcl.add(
      DataFactory.quad(
        oneQuad.subject,
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#agentGroup"),
        DataFactory.namedNode("https://some-other.pod/group#id")
      )
    );

    const agentAccess = unstable_getGroupResourceAccessAll(resourceAcl);

    expect(agentAccess).toEqual({
      "https://some.pod/group#id": {
        read: true,
        append: false,
        write: false,
        control: false,
      },
      "https://some-other.pod/group#id": {
        read: true,
        append: false,
        write: false,
        control: false,
      },
    });
  });

  it("ignores ACL rules that do not apply to a Group", () => {
    const resourceAcl = addAclRuleQuads(
      getMockDataset("https://arbitrary.pod/resource.acl"),
      "https://some.pod/group#id",
      "https://arbitrary.pod/resource",
      { read: true, append: false, write: false, control: false },
      "resource"
    );
    const agentClassRuleSubjectIri = "#arbitrary-agent-rule";
    resourceAcl.add(
      DataFactory.quad(
        DataFactory.namedNode(agentClassRuleSubjectIri),
        DataFactory.namedNode(
          "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
        ),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Authorization")
      )
    );
    resourceAcl.add(
      DataFactory.quad(
        DataFactory.namedNode(agentClassRuleSubjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#accessTo"),
        DataFactory.namedNode("https://arbitrary.pod/resource")
      )
    );
    resourceAcl.add(
      DataFactory.quad(
        DataFactory.namedNode(agentClassRuleSubjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#agent"),
        DataFactory.namedNode("https://some.pod/agent#webId")
      )
    );

    const groupAccess = unstable_getGroupResourceAccessAll(resourceAcl);

    expect(groupAccess).toEqual({
      "https://some.pod/group#id": {
        read: true,
        append: false,
        write: false,
        control: false,
      },
    });
  });

  it("ignores ACL rules that apply to a different Resource", () => {
    let resourceAcl = addAclRuleQuads(
      getMockDataset("https://some.pod/resource.acl"),
      "https://arbitrary.pod/group#id",
      "https://some-other.pod/resource",
      { read: true, append: false, write: false, control: false },
      "resource"
    );
    resourceAcl = addAclRuleQuads(
      resourceAcl,
      "https://some.pod/group#id",
      "https://some.pod/resource",
      { read: false, append: true, write: false, control: false },
      "resource"
    );

    const groupAccess = unstable_getGroupResourceAccessAll(resourceAcl);

    expect(groupAccess).toEqual({
      "https://some.pod/group#id": {
        read: false,
        append: true,
        write: false,
        control: false,
      },
    });
  });
});

describe("getGroupDefaultAccessOne", () => {
  it("returns the applicable Access Modes for a single Group", () => {
    const containerAcl = addAclRuleQuads(
      getMockDataset("https://arbitrary.pod/container/.acl"),
      "https://some.pod/group#id",
      "https://arbitrary.pod/container/",
      { read: true, append: false, write: false, control: true },
      "default"
    );

    const groupAccess = unstable_getGroupDefaultAccessOne(
      containerAcl,
      "https://some.pod/group#id"
    );

    expect(groupAccess).toEqual({
      read: true,
      append: false,
      write: false,
      control: true,
    });
  });

  it("combines Access Modes defined for a given Group in separate rules", () => {
    let containerAcl = addAclRuleQuads(
      getMockDataset("https://arbitrary.pod/container/.acl"),
      "https://some.pod/group#id",
      "https://arbitrary.pod/container/",
      { read: true, append: false, write: false, control: false },
      "default"
    );
    containerAcl = addAclRuleQuads(
      containerAcl,
      "https://some.pod/group#id",
      "https://arbitrary.pod/container/",
      { read: false, append: true, write: false, control: false },
      "default"
    );

    const groupAccess = unstable_getGroupDefaultAccessOne(
      containerAcl,
      "https://some.pod/group#id"
    );

    expect(groupAccess).toEqual({
      read: true,
      append: true,
      write: false,
      control: false,
    });
  });

  it("returns false for all Access Modes if there are no ACL rules for the given Group", () => {
    const containerAcl = addAclRuleQuads(
      getMockDataset("https://arbitrary.pod/container/.acl"),
      "https://some.pod/group#id",
      "https://arbitrary.pod/container/",
      { read: true, append: false, write: false, control: false },
      "default"
    );

    const groupAccess = unstable_getGroupDefaultAccessOne(
      containerAcl,
      "https://some-other.pod/group#id"
    );

    expect(groupAccess).toEqual({
      read: false,
      append: false,
      write: false,
      control: false,
    });
  });

  it("ignores ACL rules that apply to a different Group", () => {
    let containerAcl = addAclRuleQuads(
      getMockDataset("https://arbitrary.pod/container/.acl"),
      "https://some-other.pod/group#id",
      "https://arbitrary.pod/container/",
      { read: true, append: false, write: false, control: false },
      "default"
    );
    containerAcl = addAclRuleQuads(
      containerAcl,
      "https://some.pod/group#id",
      "https://arbitrary.pod/container/",
      { read: false, append: true, write: false, control: false },
      "default"
    );

    const groupAccess = unstable_getGroupDefaultAccessOne(
      containerAcl,
      "https://some.pod/group#id"
    );

    expect(groupAccess).toEqual({
      read: false,
      append: true,
      write: false,
      control: false,
    });
  });

  it("ignores ACL rules that apply to a different Resource", () => {
    let containerAcl = addAclRuleQuads(
      getMockDataset("https://some.pod/container/.acl"),
      "https://arbitrary.pod/group#id",
      "https://some-other.pod/container/",
      { read: true, append: false, write: false, control: false },
      "default"
    );
    containerAcl = addAclRuleQuads(
      containerAcl,
      "https://arbitrary.pod/group#id",
      "https://some.pod/container/",
      { read: false, append: true, write: false, control: false },
      "default"
    );

    const groupAccess = unstable_getGroupDefaultAccessOne(
      containerAcl,
      "https://arbitrary.pod/group#id"
    );

    expect(groupAccess).toEqual({
      read: false,
      append: true,
      write: false,
      control: false,
    });
  });
});

describe("getGroupDefaultAccessAll", () => {
  it("returns the applicable Access Modes for all Groups for whom Access Modes have been defined", () => {
    let containerAcl = addAclRuleQuads(
      getMockDataset("https://arbitrary.pod/container/.acl"),
      "https://some-other.pod/group#id",
      "https://arbitrary.pod/container/",
      { read: true, append: false, write: false, control: false },
      "default"
    );
    containerAcl = addAclRuleQuads(
      containerAcl,
      "https://some.pod/group#id",
      "https://arbitrary.pod/container/",
      { read: false, append: true, write: false, control: false },
      "default"
    );

    const groupAccess = unstable_getGroupDefaultAccessAll(containerAcl);

    expect(groupAccess).toEqual({
      "https://some.pod/group#id": {
        read: false,
        append: true,
        write: false,
        control: false,
      },
      "https://some-other.pod/group#id": {
        read: true,
        append: false,
        write: false,
        control: false,
      },
    });
  });

  it("combines Access Modes defined for the same Group in different Rules", () => {
    let containerAcl = addAclRuleQuads(
      getMockDataset("https://arbitrary.pod/container/.acl"),
      "https://some.pod/group#id",
      "https://arbitrary.pod/container/",
      { read: true, append: false, write: false, control: false },
      "default"
    );
    containerAcl = addAclRuleQuads(
      containerAcl,
      "https://some.pod/group#id",
      "https://arbitrary.pod/container/",
      { read: false, append: true, write: false, control: false },
      "default"
    );

    const groupAccess = unstable_getGroupDefaultAccessAll(containerAcl);

    expect(groupAccess).toEqual({
      "https://some.pod/group#id": {
        read: true,
        append: true,
        write: false,
        control: false,
      },
    });
  });

  it("returns Access Modes for all Groups even if they are assigned in the same Rule", () => {
    const containerAcl = addAclRuleQuads(
      getMockDataset("https://arbitrary.pod/container/.acln"),
      "https://some.pod/group#id",
      "https://arbitrary.pod/container/",
      { read: true, append: false, write: false, control: false },
      "default"
    );
    const oneQuad = Array.from(containerAcl)[0];
    containerAcl.add(
      DataFactory.quad(
        oneQuad.subject,
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#agentGroup"),
        DataFactory.namedNode("https://some-other.pod/group#id")
      )
    );

    const groupAccess = unstable_getGroupDefaultAccessAll(containerAcl);

    expect(groupAccess).toEqual({
      "https://some.pod/group#id": {
        read: true,
        append: false,
        write: false,
        control: false,
      },
      "https://some-other.pod/group#id": {
        read: true,
        append: false,
        write: false,
        control: false,
      },
    });
  });

  it("ignores ACL rules that do not apply to a Group", () => {
    const containerAcl = addAclRuleQuads(
      getMockDataset("https://arbitrary.pod/container/.acl"),
      "https://some.pod/group#id",
      "https://arbitrary.pod/container/",
      { read: true, append: false, write: false, control: false },
      "default"
    );
    const agentClassRuleSubjectIri = "#arbitrary-agent-rule";
    containerAcl.add(
      DataFactory.quad(
        DataFactory.namedNode(agentClassRuleSubjectIri),
        DataFactory.namedNode(
          "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
        ),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Authorization")
      )
    );
    containerAcl.add(
      DataFactory.quad(
        DataFactory.namedNode(agentClassRuleSubjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#default"),
        DataFactory.namedNode("https://arbitrary.pod/container/")
      )
    );
    containerAcl.add(
      DataFactory.quad(
        DataFactory.namedNode(agentClassRuleSubjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#agent"),
        DataFactory.namedNode("https://some.pod/agent#webId")
      )
    );

    const groupAccess = unstable_getGroupDefaultAccessAll(containerAcl);

    expect(groupAccess).toEqual({
      "https://some.pod/group#id": {
        read: true,
        append: false,
        write: false,
        control: false,
      },
    });
  });

  it("ignores ACL rules that apply to a different Resource", () => {
    let containerAcl = addAclRuleQuads(
      getMockDataset("https://some.pod/container/.acl"),
      "https://arbitrary.pod/group#id",
      "https://some-other.pod/container/",
      { read: true, append: false, write: false, control: false },
      "default"
    );
    containerAcl = addAclRuleQuads(
      containerAcl,
      "https://some.pod/group#id",
      "https://some.pod/container/",
      { read: false, append: true, write: false, control: false },
      "default"
    );

    const groupAccess = unstable_getGroupDefaultAccessAll(containerAcl);

    expect(groupAccess).toEqual({
      "https://some.pod/group#id": {
        read: false,
        append: true,
        write: false,
        control: false,
      },
    });
  });
});
