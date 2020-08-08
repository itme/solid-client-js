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

import {
  AclDataset,
  Access,
  AclRule,
  WithAcl,
  WithResourceInfo,
  IriString,
  UrlString,
  WebId,
  WithChangeLog,
} from "../interfaces";
import {
  internal_getAclRules,
  internal_getDefaultAclRulesForResource,
  internal_duplicateAclRule,
  internal_initialiseAclRule,
  internal_getAccess,
  internal_combineAccessModes,
  internal_getResourceAclRulesForResource,
  internal_removeEmptyAclRules,
  hasResourceAcl,
  hasFallbackAcl,
  getResourceAcl,
  getFallbackAcl,
  internal_getAclRulesForIri,
  internal_getAccessByIri,
} from "./acl";
import { getThingAll, setThing } from "../thing/thing";
import { removeIri, removeAll } from "../thing/remove";
import { getIriAll } from "../thing/get";
import { setIri } from "../thing/set";

import { acl } from "../constants";

/**
 * Find out what Access Modes have been granted to a given Group of agents specifically for a given Resource.
 *
 * Keep in mind that this function will not tell you what access members of the given Group have through other ACL rules, e.g. public permissions.
 *
 * Also, please note that this function is still experimental: its API can change in non-major releases.
 *
 * @param resourceInfo Information about the Resource to which the given Group may have been granted access.
 * @param group URL of the Group for which to retrieve what access it has to the Resource.
 * @returns Which Access Modes have been granted to the Group specifically for the given Resource, or `null` if it could not be determined (e.g. because the current user does not have Control Access to a given Resource or its Container).
 */
export function getGroupAccess(
  resourceInfo: WithAcl & WithResourceInfo,
  group: UrlString
): Access | null {
  if (hasResourceAcl(resourceInfo)) {
    return getGroupResourceAccess(resourceInfo.internal_acl.resourceAcl, group);
  }
  if (hasFallbackAcl(resourceInfo)) {
    return getGroupDefaultAccess(resourceInfo.internal_acl.fallbackAcl, group);
  }
  return null;
}

/**
 * Find out what Access Modes have been granted to specific Groups of agents for a given Resource.
 *
 * Keep in mind that this function will not tell you what access members of each Group have through other ACL rules, e.g. public permissions.
 *
 * Also, please note that this function is still experimental: its API can change in non-major releases.
 *
 * @param resourceInfo Information about the Resource to which the given Group may have been granted access.
 * @returns Which Access Modes have been granted to which Groups specifically for the given Resource, or `null` if it could not be determined (e.g. because the current user does not have Control Access to a given Resource or its Container).
 */
export function getGroupAccessAll(
  resourceInfo: WithAcl & WithResourceInfo
): Record<IriString, Access> | null {
  if (hasResourceAcl(resourceInfo)) {
    const resourceAcl = getResourceAcl(resourceInfo);
    return getGroupResourceAccessAll(resourceAcl);
  }
  if (hasFallbackAcl(resourceInfo)) {
    const fallbackAcl = getFallbackAcl(resourceInfo);
    return getGroupDefaultAccessAll(fallbackAcl);
  }
  return null;
}

/**
 * Given an ACL SolidDataset, find out which access modes it provides to a Group for its associated Resource.
 *
 * Keep in mind that this function will not tell you:
 * - what access members of the given Group have through other ACL rules, e.g. public permissions.
 * - what access members of the given Group have to child Resources, in case the associated Resource is a Container (see [[getGroupDefaultAccessModes]] for that).
 *
 * Also, please note that this function is still experimental: its API can change in non-major releases.
 *
 * @param aclDataset The SolidDataset that contains Access-Control List rules.
 * @param group URL of the Group for which to retrieve what access it has to the Resource.
 * @returns Which Access Modes have been granted to the Group specifically for the Resource the given ACL SolidDataset is associated with.
 */
export function getGroupResourceAccess(
  aclDataset: AclDataset,
  group: UrlString
): Access {
  const allRules = internal_getAclRules(aclDataset);
  const resourceRules = internal_getResourceAclRulesForResource(
    allRules,
    aclDataset.internal_accessTo
  );
  const groupResourceRules = getGroupAclRuleForGroup(resourceRules, group);
  const groupAccessModes = groupResourceRules.map(internal_getAccess);
  return internal_combineAccessModes(groupAccessModes);
}

/**
 * Given an ACL SolidDataset, find out which access modes it provides to specific Groups for the associated Resource.
 *
 * Keep in mind that this function will not tell you:
 * - what access arbitrary members of these Groups might have been given through other ACL rules, e.g. public permissions.
 * - what access arbitrary members of these Groups have to child Resources, in case the associated Resource is a Container.
 *
 * Also, please note that this function is still experimental: its API can change in non-major releases.
 *
 * @param aclDataset The SolidDataset that contains Access-Control List rules.
 * @returns Which Access Modes have been granted to which Groups specifically for the Resource the given ACL SolidDataset is associated with.
 */
export function getGroupResourceAccessAll(
  aclDataset: AclDataset
): Record<UrlString, Access> {
  const allRules = internal_getAclRules(aclDataset);
  const resourceRules = internal_getResourceAclRulesForResource(
    allRules,
    aclDataset.internal_accessTo
  );
  return getAccessByGroup(resourceRules);
}

/**
 * Given an ACL SolidDataset, find out which access modes it provides to a given Group for the associated Container Resource's child Resources.
 *
 * Keep in mind that this function will not tell you:
 * - what access members of the given Group have through other ACL rules, e.g. public permissions.
 * - what access members of the given Group have to the Container Resource itself (see [[getGroupResourceAccess]] for that).
 *
 * Also, please note that this function is still experimental: its API can change in non-major releases.
 *
 * @param aclDataset The SolidDataset that contains Access-Control List rules for a certain Container.
 * @param group URL of the Group for which to retrieve what access it has to the child Resources of the given Container.
 * @returns Which Access Modes have been granted to the Group specifically for the children of the Container associated with the given ACL SolidDataset.
 */
export function getGroupDefaultAccess(
  aclDataset: AclDataset,
  group: UrlString
): Access {
  const allRules = internal_getAclRules(aclDataset);
  const defaultRules = internal_getDefaultAclRulesForResource(
    allRules,
    aclDataset.internal_accessTo
  );
  const groupDefaultRules = getGroupAclRuleForGroup(defaultRules, group);
  const groupAccessModes = groupDefaultRules.map(internal_getAccess);
  return internal_combineAccessModes(groupAccessModes);
}

/**
 * Given an ACL SolidDataset, find out which access modes it provides to specific Groups for the associated Container Resource's child Resources.
 *
 * Keep in mind that this function will not tell you:
 * - what access arbitrary members of these Groups have through other ACL rules, e.g. public permissions.
 * - what access arbitrary members of these Groups have to the Container Resource itself (see [[getGroupResourceAccessAll]] for that).
 *
 * Also, please note that this function is still experimental: its API can change in non-major releases.
 *
 * @param aclDataset The SolidDataset that contains Access-Control List rules for a certain Container.
 * @returns Which Access Modes have been granted to which Groups specifically for the children of the Container associated with the given ACL SolidDataset.
 */
export function getGroupDefaultAccessAll(
  aclDataset: AclDataset
): Record<UrlString, Access> {
  const allRules = internal_getAclRules(aclDataset);
  const defaultRules = internal_getDefaultAclRulesForResource(
    allRules,
    aclDataset.internal_accessTo
  );
  return getAccessByGroup(defaultRules);
}

function getGroupAclRuleForGroup(
  rules: AclRule[],
  group: UrlString
): AclRule[] {
  return internal_getAclRulesForIri(rules, group, acl.agentGroup);
}

function getAccessByGroup(aclRules: AclRule[]): Record<IriString, Access> {
  return internal_getAccessByIri(aclRules, acl.agentGroup);
}

export function setGroupResourceAccess(
  aclDataset: AclDataset,
  group: WebId,
  access: Access
): AclDataset & WithChangeLog {
  // First make sure that none of the pre-existing rules in the given ACL SolidDataset
  // give the Group access to the Resource:
  let filteredAcl = aclDataset;
  getThingAll(aclDataset).forEach((aclRule) => {
    // Obtain both the Rule that no longer includes the given Group,
    // and a new Rule that includes all ACL Quads
    // that do not pertain to the given Group-Resource combination.
    // Note that usually, the latter will no longer include any meaningful statements;
    // we'll clean them up afterwards.
    const [filteredRule, remainingRule] = removeGroupFromRule(
      aclRule,
      group,
      aclDataset.internal_accessTo,
      "resource"
    );
    filteredAcl = setThing(filteredAcl, filteredRule);
    filteredAcl = setThing(filteredAcl, remainingRule);
  });

  // Create a new Rule that only grants the given Group the given Access Modes:
  let newRule = internal_initialiseAclRule(access);
  newRule = setIri(newRule, acl.accessTo, aclDataset.internal_accessTo);
  newRule = setIri(newRule, acl.agentGroup, group);
  const updatedAcl = setThing(filteredAcl, newRule);

  // Remove any remaining Rules that do not contain any meaningful statements:
  const cleanedAcl = internal_removeEmptyAclRules(updatedAcl);

  return cleanedAcl;
}

function removeGroupFromRule(
  rule: AclRule,
  group: WebId,
  resourceIri: IriString,
  ruleType: "resource" | "default"
): [AclRule, AclRule] {
  // If the existing Rule does not apply to the given Group, we don't need to split up.
  // Without this check, we'd be creating a new rule for the given Group (ruleForOtherTargets)
  // that would give it access it does not currently have:
  if (!getIriAll(rule, acl.agentGroup).includes(group)) {
    const emptyRule = internal_initialiseAclRule({
      read: false,
      append: false,
      write: false,
      control: false,
    });
    return [rule, emptyRule];
  }
  // The existing rule will keep applying to Groups other than the given one:
  const ruleWithoutGroup = removeIri(rule, acl.agentGroup, group);
  // The group already had some access in the rule, so duplicate it...
  let ruleForOtherTargets = internal_duplicateAclRule(rule);
  // ...but remove access to the original Resource:
  ruleForOtherTargets = removeIri(
    ruleForOtherTargets,
    ruleType === "resource" ? acl.accessTo : acl.default,
    resourceIri
  );
  // Only apply the new Rule to the given Group (because the existing Rule covers the others)
  ruleForOtherTargets = setIri(ruleForOtherTargets, acl.agent, group);
  ruleForOtherTargets = removeAll(ruleForOtherTargets, acl.agentClass);
  ruleForOtherTargets = removeAll(ruleForOtherTargets, acl.agentGroup);

  return [ruleWithoutGroup, ruleForOtherTargets];
}
