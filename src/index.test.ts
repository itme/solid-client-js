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
  unstable_fetchFile,
  unstable_deleteFile,
  unstable_saveFileInContainer,
  unstable_overwriteFile,
  createLitDataset,
  fetchLitDataset,
  unstable_fetchResourceInfoWithAcl,
  isContainer,
  isLitDataset,
  getContentType,
  getFetchedFrom,
  saveLitDatasetAt,
  saveLitDatasetInContainer,
  unstable_saveAclFor,
  unstable_deleteAclFor,
  getThingOne,
  getThingAll,
  setThing,
  removeThing,
  createThing,
  asUrl,
  asIri,
  getUrlOne,
  getIriOne,
  getBooleanOne,
  getDatetimeOne,
  getDecimalOne,
  getIntegerOne,
  getStringWithLocaleOne,
  getStringNoLocaleOne,
  getUrlAll,
  getIriAll,
  getBooleanAll,
  getDatetimeAll,
  getDecimalAll,
  getIntegerAll,
  getStringWithLocaleAll,
  getStringNoLocaleAll,
  getLiteralOne,
  getNamedNodeOne,
  getLiteralAll,
  getNamedNodeAll,
  addUrl,
  addIri,
  addBoolean,
  addDatetime,
  addDecimal,
  addInteger,
  addStringWithLocale,
  addStringNoLocale,
  addLiteral,
  addNamedNode,
  setUrl,
  setIri,
  setBoolean,
  setDatetime,
  setDecimal,
  setInteger,
  setStringWithLocale,
  setStringNoLocale,
  setLiteral,
  setNamedNode,
  removeAll,
  removeUrl,
  removeIri,
  removeBoolean,
  removeDatetime,
  removeDecimal,
  removeInteger,
  removeStringWithLocale,
  removeStringNoLocale,
  removeLiteral,
  removeNamedNode,
  unstable_fetchLitDatasetWithAcl,
  unstable_hasFallbackAcl,
  unstable_getFallbackAcl,
  unstable_hasResourceAcl,
  unstable_getResourceAcl,
  unstable_createAclFromFallbackAcl,
  unstable_getAgentAccessOne,
  unstable_getAgentAccessAll,
  unstable_getAgentResourceAccessOne,
  unstable_getAgentResourceAccessAll,
  unstable_setAgentResourceAccess,
  unstable_getAgentDefaultAccessOne,
  unstable_getAgentDefaultAccessAll,
  unstable_setAgentDefaultAccess,
  unstable_getPublicAccess,
  unstable_getPublicResourceAccess,
  unstable_getPublicDefaultAccess,
  unstable_hasAccessibleAcl,
  unstable_getGroupAccessOne,
  unstable_getGroupAccessAll,
  unstable_getGroupResourceAccessOne,
  unstable_getGroupResourceAccessAll,
  unstable_getGroupDefaultAccessOne,
  unstable_getGroupDefaultAccessAll,
  // Deprecated functions still exported for backwards compatibility:
  getStringUnlocalizedOne,
  getStringUnlocalizedAll,
  addStringUnlocalized,
  setStringUnlocalized,
  removeStringUnlocalized,
  getStringInLocaleOne,
  getStringInLocaleAll,
  addStringInLocale,
  setStringInLocale,
  removeStringInLocale,
} from "./index";
import { expects } from "rdf-namespaces/dist/hydra";

// These tests aren't too useful in preventing bugs, but they work around this issue:
// https://github.com/facebook/jest/issues/10032
it("exports the public API from the entry file", () => {
  expect(unstable_fetchFile).toBeDefined();
  expect(unstable_deleteFile).toBeDefined();
  expect(unstable_saveFileInContainer).toBeDefined();
  expect(unstable_overwriteFile).toBeDefined();
  expect(createLitDataset).toBeDefined();
  expect(fetchLitDataset).toBeDefined();
  expect(unstable_fetchResourceInfoWithAcl).toBeDefined();
  expect(isContainer).toBeDefined();
  expect(isLitDataset).toBeDefined();
  expect(getContentType).toBeDefined();
  expect(getFetchedFrom).toBeDefined();
  expect(saveLitDatasetAt).toBeDefined();
  expect(saveLitDatasetInContainer).toBeDefined();
  expect(unstable_saveAclFor).toBeDefined();
  expect(unstable_deleteAclFor).toBeDefined();
  expect(getThingOne).toBeDefined();
  expect(getThingAll).toBeDefined();
  expect(setThing).toBeDefined();
  expect(removeThing).toBeDefined();
  expect(createThing).toBeDefined();
  expect(asUrl).toBeDefined();
  expect(asIri).toBeDefined();
  expect(getUrlOne).toBeDefined();
  expect(getIriOne).toBeDefined();
  expect(getBooleanOne).toBeDefined();
  expect(getDatetimeOne).toBeDefined();
  expect(getDecimalOne).toBeDefined();
  expect(getIntegerOne).toBeDefined();
  expect(getStringWithLocaleOne).toBeDefined();
  expect(getStringNoLocaleOne).toBeDefined();
  expect(getUrlAll).toBeDefined();
  expect(getIriAll).toBeDefined();
  expect(getBooleanAll).toBeDefined();
  expect(getDatetimeAll).toBeDefined();
  expect(getDecimalAll).toBeDefined();
  expect(getIntegerAll).toBeDefined();
  expect(getStringWithLocaleAll).toBeDefined();
  expect(getStringNoLocaleAll).toBeDefined();
  expect(getLiteralOne).toBeDefined();
  expect(getNamedNodeOne).toBeDefined();
  expect(getLiteralAll).toBeDefined();
  expect(getNamedNodeAll).toBeDefined();
  expect(addUrl).toBeDefined();
  expect(addIri).toBeDefined();
  expect(addBoolean).toBeDefined();
  expect(addDatetime).toBeDefined();
  expect(addDecimal).toBeDefined();
  expect(addInteger).toBeDefined();
  expect(addStringWithLocale).toBeDefined();
  expect(addStringNoLocale).toBeDefined();
  expect(addLiteral).toBeDefined();
  expect(addNamedNode).toBeDefined();
  expect(setUrl).toBeDefined();
  expect(setIri).toBeDefined();
  expect(setBoolean).toBeDefined();
  expect(setDatetime).toBeDefined();
  expect(setDecimal).toBeDefined();
  expect(setInteger).toBeDefined();
  expect(setStringWithLocale).toBeDefined();
  expect(setStringNoLocale).toBeDefined();
  expect(setLiteral).toBeDefined();
  expect(setNamedNode).toBeDefined();
  expect(removeAll).toBeDefined();
  expect(removeUrl).toBeDefined();
  expect(removeIri).toBeDefined();
  expect(removeBoolean).toBeDefined();
  expect(removeDatetime).toBeDefined();
  expect(removeDecimal).toBeDefined();
  expect(removeInteger).toBeDefined();
  expect(removeStringWithLocale).toBeDefined();
  expect(removeStringNoLocale).toBeDefined();
  expect(removeLiteral).toBeDefined();
  expect(removeNamedNode).toBeDefined();
  expect(unstable_fetchLitDatasetWithAcl).toBeDefined();
  expect(unstable_hasFallbackAcl).toBeDefined();
  expect(unstable_getFallbackAcl).toBeDefined();
  expect(unstable_hasResourceAcl).toBeDefined();
  expect(unstable_getResourceAcl).toBeDefined();
  expect(unstable_createAclFromFallbackAcl).toBeDefined();
  expect(unstable_getAgentAccessOne).toBeDefined();
  expect(unstable_getAgentAccessAll).toBeDefined();
  expect(unstable_getAgentResourceAccessOne).toBeDefined();
  expect(unstable_getAgentResourceAccessAll).toBeDefined();
  expect(unstable_setAgentResourceAccess).toBeDefined();
  expect(unstable_getAgentDefaultAccessOne).toBeDefined();
  expect(unstable_getAgentDefaultAccessAll).toBeDefined();
  expect(unstable_setAgentDefaultAccess).toBeDefined();
  expect(unstable_getPublicAccess).toBeDefined();
  expect(unstable_getPublicResourceAccess).toBeDefined();
  expect(unstable_getPublicDefaultAccess).toBeDefined();
  expect(unstable_hasAccessibleAcl).toBeDefined();
  expect(unstable_getGroupAccessOne).toBeDefined();
  expect(unstable_getGroupAccessAll).toBeDefined();
  expect(unstable_getGroupResourceAccessOne).toBeDefined();
  expect(unstable_getGroupResourceAccessAll).toBeDefined();
  expect(unstable_getGroupDefaultAccessOne).toBeDefined();
  expect(unstable_getGroupDefaultAccessAll).toBeDefined();
});

it("still exports deprecated methods", () => {
  expect(getStringInLocaleOne).toBeDefined();
  expect(getStringUnlocalizedOne).toBeDefined();
  expect(getStringInLocaleAll).toBeDefined();
  expect(getStringUnlocalizedAll).toBeDefined();
  expect(addStringInLocale).toBeDefined();
  expect(addStringUnlocalized).toBeDefined();
  expect(setStringInLocale).toBeDefined();
  expect(setStringUnlocalized).toBeDefined();
  expect(removeStringInLocale).toBeDefined();
  expect(removeStringUnlocalized).toBeDefined();
});
