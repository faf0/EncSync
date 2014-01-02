package misc;

import java.io.StringWriter;

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

/**
 * Pretty print extension for json-simple library.
 * Elad Tabak is the author of the original code.
 * Adapted by Fabian Foerg.
 * 
 * @author Elad Tabak
 * @author Fabian Foerg
 */
public final class JSONPrettyPrintWriter extends StringWriter {
    private int indent;

    /**
     * Creates a new JSON pretty print writer.
     */
    public JSONPrettyPrintWriter() {
        indent = 0;
    }

    /**
     * {inheritDoc}
     */
    @Override
    public void write(int c) {
        switch (c) {
        case '[':
        case '{':
            super.write(c);
            super.write('\n');
            indent++;
            writeIndentation();
            break;

        case ',':
            super.write(c);
            super.write('\n');
            writeIndentation();
            break;

        case ']':
        case '}':
            super.write('\n');
            indent--;
            writeIndentation();
            super.write(c);
            break;

        default:
            super.write(c);
            break;
        }
    }

    /**
     * Writes the indentation white spaces.
     */
    private void writeIndentation() {
        for (int i = 0; i < indent; i++) {
            super.write("  ");
        }
    }
}
