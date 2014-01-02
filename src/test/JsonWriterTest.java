/*
 * Copyright (C) 2012, Tonian, Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package test;

import static org.junit.Assert.assertEquals;

import org.junit.BeforeClass;
import org.junit.Test;

import misc.JSONPrettyPrintWriter;

/**
 * Unit tests for the JSONPrettyPrintWriter class.
 * 
 * @author Elad Tabak
 * @author Fabian Foerg
 * @version Jan 01, 2014
 * @since Genesis
 */
public class JsonWriterTest {
    private static JSONPrettyPrintWriter writer;

    @BeforeClass
    public static void beforeClass() {
	writer = new JSONPrettyPrintWriter();
    }

    @Test
    public void testIndentation() {
	// @formatter:off
	final String json =
		"{"                             + '\n' +
		"   \"key1\":\"value1\","       + '\n' +
		"   \"key2\":["                 + '\n' +
		"      \"value2a\","            + '\n' +
		"      \"value2b\""             + '\n' +
		"   ],"                         + '\n' +
		"   \"key3\":{"                 + '\n' +
		"      \"key4\":\"value4\""     + '\n' +
		"   },"                         + '\n' +
		"   \"key5\":{"                 + '\n' +
		"      \"key6\":{"              + '\n' +
		"         \"key7\":true"        + '\n' +
		"      }"                       + '\n' +
		"   }"                          + '\n' +
		"}";
	// @formatter:on
	String jsonNoWhiteChars = json.replaceAll(" ", "").replaceAll("\n", "");
	for (byte c : jsonNoWhiteChars.getBytes()) {
	    writer.append((char) c);
	}
	assertEquals(json, writer.toString());
    }
}
