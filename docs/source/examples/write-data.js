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

import { getSolidDataset, getThing } from "@inrupt/solid-client";

const profileResource = await getSolidDataset(
  "https://vincentt.inrupt.net/profile/card"
);

const profile = getThing(
  profileResource,
  "https://vincentt.inrupt.net/profile/card#me"
);

// BEGIN-EXAMPLE-WRITE-DATA

import {
  setStringUnlocalised,
  setThing,
  saveSolidDatasetAt,
} from "@inrupt/solid-client";
import { FOAF } from "@inrupt/vocab-common-rdf";

/*
   Start with a previously fetched Thing (i.e. profile).

   Use setStringUnlocalised to create a NEW Thing 
     (i.e., updatedProfile) with the updated name data.

   The passed-in Thing (i.e. profile) is unmodified.
*/

const updatedProfile = setStringUnlocalised(profile, FOAF.name, "Vincent");

/*
   Create a new dataset (i.e., updatedProfileResource) from 
     a previously fetched dataset (i.e., profileResource) and 
     the updated profile data.
   If the profile data already exists in the existing dataset,
     the new profile data replaces the existing profile data
     in the newly created dataset.
   The passed-in dataset (i.e. profileResource) is unmodified.
*/
const updatedProfileResource = setThing(profileResource, updatedProfile);

// Save the new dataset.
await saveSolidDatasetAt(
  "https://vincentt.inrupt.net/profile/card",
  updatedProfileResource
);

// END-EXAMPLE-WRITE-DATA
