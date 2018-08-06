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

import java.io.IOException;

/**
 * @author wglas
 *
 */
public class PKCS15Exception extends IOException {

    private static final long serialVersionUID = 7500833559613739356L;

    /**
     * This error code is for errors, which do originate from a
     * smart card operation.
     */
    public static final int ERROR_UNKNOWN = -1;
    public static final int ERROR_OK = 0x9000;
    public static final int ERROR_EEPROM_WEAK = 0x9001;

    public static final int ERROR_FILE_DEACTIVATED              = 0x6283;
    public static final int ERROR_FILE_TERMINATED               = 0x6285;

    public static final int ERROR_AUTHENTICATION_FAILED         = 0x6300;

    public static final int ERROR_EEPROM_ERROR                  = 0x6581;

    public static final int ERROR_LC_INVALID                    = 0x6700;

    public static final int ERROR_LOGICAL_CHANNEL_NOT_SUPPORTED = 0x6881;
    public static final int ERROR_SM_MODE_NOT_SUPPORTED         = 0x6882;
    public static final int ERROR_CHAINING_ERROR                = 0x6884;

    public static final int ERROR_INVALID_COMMAND               = 0x6981;
    public static final int ERROR_ACCES_DENIED                  = 0x6982;
    public static final int ERROR_BS_OBJECT_BLOCKED             = 0x6983;
    public static final int ERROR_BS_OBJECT_INVALID             = 0x6984;
    public static final int ERROR_BS_NO_RANDOM_NUMBER           = 0x6985;
    public static final int ERROR_BS_NO_CURRENT_EF              = 0x6986;
    public static final int ERROR_SM_KEY_NOT_FOUND              = 0x6987;
    public static final int ERROR_SM_KEY_INVALID                = 0x6988;

    public static final int ERROR_INVALID_PARAMETER             = 0x6A80;
    public static final int ERROR_FUNCTION_NOT_SUPPORTED        = 0x6A81;
    public static final int ERROR_FILE_NOT_FOUND                = 0x6A82;
    public static final int ERROR_RECORD_NOT_FOUND              = 0x6A83;
    public static final int ERROR_MEMORY_OVERFLOW               = 0x6A84;
    public static final int ERROR_LC_TLV_MISMATCH               = 0x6A85;
    public static final int ERROR_P1_P2_INVALID                 = 0x6A86;
    public static final int ERROR_LC_P1_P2_MISMATCH             = 0x6A87;
    public static final int ERROR_DATA_OBJECT_NOT_FOUND         = 0x6A88;
    public static final int ERROR_FILE_EXISTS                   = 0x6A89;
    public static final int ERROR_DF_EXISTS                     = 0x6A8A;

    public static final int ERROR_LE_INVALID                    = 0x6C00;
    public static final int ERROR_INS_INVALID                   = 0x6D00;
    public static final int ERROR_CLA_INVALID                   = 0x6E00;

    public static final int ERROR_TECHNICAL_ERROR               = 0x6F00;
    public static final int ERROR_CHECKSUM                      = 0x6F81;
    public static final int ERROR_XRAM_OVERFLOW                 = 0x6F82;
    public static final int ERROR_TRANSACTION_NOT_SUPPORTE      = 0x6F83;
    public static final int ERROR_PROTECTION_FAULT              = 0x6F84;
    public static final int ERROR_PK_API_FAULT                  = 0x6F85;
    public static final int ERROR_KEY_NOT_FOUND                 = 0x6F86;
    public static final int ERROR_HARDWARE_MANIPULATION_DETECTED= 0x6F87;
    public static final int ERROR_TRANSACTION_BUFFER_OVERFLOW   = 0x6F88;
    public static final int ERROR_ASSERTION_FAILED              = 0x6FFF;

    public static final int ERROR_INCREASE_DECREASE_EXCEEDED    = 0x9850;

    public static final int ERROR_TRANSPORT_ERROR = 0xFFFF;

    private final int errorCode;

    /**
     * @param errorCode The error code as returned by the token.
     */
    public PKCS15Exception(int errorCode) {
        super("card error [0x"+Integer.toHexString(errorCode)+"]");
        this.errorCode = errorCode;
    }

    /**
     * @param msg The error message.
     * @param cause The root cause.
     * @param errorCode The error code as returned by the token.
     */
    public PKCS15Exception(String msg, Throwable cause, int errorCode) {
        super(msg + " [0x"+Integer.toHexString(errorCode)+"]", cause);
        this.errorCode = errorCode;
    }

    /**
     * @param msg
     * @param errorCode The error code as returned by the token.
     */
    public PKCS15Exception(String msg, int errorCode) {
        super(msg + " [0x"+Integer.toHexString(errorCode)+"]");
        this.errorCode = errorCode;
    }

    /**
     * @param cause The root cause of the exception.
     * @param errorCode The error code as returned by the token.
     */
    public PKCS15Exception(Throwable cause, int errorCode) {
        super("card error [0x"+Integer.toHexString(errorCode)+"]", cause);
        this.errorCode = errorCode;
    }

    /**
     * Translate a CardException in to a PKCS15Excetion by setting the
     * error code to {@link #ERROR_TRANSPORT_ERROR}.
     *
     * @param msg The error message.
     * @param cause The card exception raised by the JAVA smartcard API.
     */
    protected PKCS15Exception(String msg, Throwable cause) {
        super(msg,cause);
        this.errorCode = ERROR_TRANSPORT_ERROR;
    }

    /**
     * @return The error code as returned by the token.
     */
    public int getErrorCode() {
        return this.errorCode;
    }
}
