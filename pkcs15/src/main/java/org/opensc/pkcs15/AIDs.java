/***********************************************************
 * $Id$
 * 
 * PKCS#15 cryptographic provider of the opensc project.
 * http://www.opensc-project.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Created: 26.12.2007
 * 
 ***********************************************************/

package org.opensc.pkcs15;

/**
 * This class holds all known application IDs.
 * 
 * @author wglas
 */
public abstract class AIDs {

    /**
     * The application ID of PKCS#15 applications.
     */
    public static final byte[] PKCS15_AID =
        new byte[] {  // PKCS#15 RID: A0 00 00 00 63
                      (byte)0xA0, 0x00, 0x00, 0x00, 0x63,
                      // "PKCS-15
                      0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35 };
}
