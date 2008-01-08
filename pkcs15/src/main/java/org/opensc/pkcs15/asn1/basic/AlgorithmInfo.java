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
 * Created: 30.12.2007
 * 
 ***********************************************************/

package org.opensc.pkcs15.asn1.basic;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.opensc.pkcs15.asn1.helper.IntegerHelper;

/**
 * The ASN.1 representation of the polymorphic KeyIdentifier.
 * 
 * <PRE>
 * AlgorithmInfo ::= SEQUENCE {
 *         reference            Reference,
 *         algorithm            PKCS15-ALGORITHM.&id({AlgorithmSet}),
 *         parameters           PKCS15-ALGORITHM.&Parameters({AlgorithmSet}{@algorithm}),
 *         supportedOperations PKCS15-ALGORITHM.&Operations({AlgorithmSet}{@algorithm}),
 *         algId                PKCS15-ALGORITHM.&objectIdentifier({AlgorithmSet}{@algorithm})
 *                              OPTIONAL,
 *         algRef               Reference OPTIONAL
 *         }
 * PKCS15-ALGORITHM ::= CLASS {
 *          &id INTEGER UNIQUE,
 *          &Parameters,
 *          &Operations Operations,
 *          &objectIdentifier OBJECT IDENTIFIER OPTIONAL
 * } WITH SYNTAX {
 *           PARAMETERS &Parameters OPERATIONS &Operations ID &id [OID &objectIdentifier]}
 * </PRE>
 * 
 * @author wglas
 */
public abstract class AlgorithmInfo extends ASN1Encodable {

    public static final int nullAlgorithmId = -1;
    
    // algorithm IDs from PKCS#11
    /* the following mechanism types are defined: */
    public static final int CKM_RSA_PKCS_KEY_PAIR_GEN      = 0x00000000;
    public static final int CKM_RSA_PKCS                   = 0x00000001;
    public static final int CKM_RSA_9796                   = 0x00000002;
    public static final int CKM_RSA_X_509                  = 0x00000003;
    
    /* CKM_MD2_RSA_PKCS, CKM_MD5_RSA_PKCS, and CKM_SHA1_RSA_PKCS
     * are new for v2.0.  They are mechanisms which hash and sign */
    public static final int CKM_MD2_RSA_PKCS               = 0x00000004;
    public static final int CKM_MD5_RSA_PKCS               = 0x00000005;
    public static final int CKM_SHA1_RSA_PKCS              = 0x00000006;
    
    /* CKM_RIPEMD128_RSA_PKCS, CKM_RIPEMD160_RSA_PKCS, and
     * CKM_RSA_PKCS_OAEP are new for v2.10 */
    public static final int CKM_RIPEMD128_RSA_PKCS         = 0x00000007;
    public static final int CKM_RIPEMD160_RSA_PKCS         = 0x00000008;
    public static final int CKM_RSA_PKCS_OAEP              = 0x00000009;
    
    /* CKM_RSA_X9_31_KEY_PAIR_GEN, CKM_RSA_X9_31, CKM_SHA1_RSA_X9_31,
     * CKM_RSA_PKCS_PSS, and CKM_SHA1_RSA_PKCS_PSS are new for v2.11 */
    public static final int CKM_RSA_X9_31_KEY_PAIR_GEN     = 0x0000000A;
    public static final int CKM_RSA_X9_31                  = 0x0000000B;
    public static final int CKM_SHA1_RSA_X9_31             = 0x0000000C;
    public static final int CKM_RSA_PKCS_PSS               = 0x0000000D;
    public static final int CKM_SHA1_RSA_PKCS_PSS          = 0x0000000E;
    
    public static final int CKM_DSA_KEY_PAIR_GEN           = 0x00000010;
    public static final int CKM_DSA                        = 0x00000011;
    public static final int CKM_DSA_SHA1                   = 0x00000012;
    public static final int CKM_DH_PKCS_KEY_PAIR_GEN       = 0x00000020;
    public static final int CKM_DH_PKCS_DERIVE             = 0x00000021;
    
    /* CKM_X9_42_DH_KEY_PAIR_GEN, CKM_X9_42_DH_DERIVE,
     * CKM_X9_42_DH_HYBRID_DERIVE, and CKM_X9_42_MQV_DERIVE are new for
     * v2.11 */
    public static final int CKM_X9_42_DH_KEY_PAIR_GEN      = 0x00000030;
    public static final int CKM_X9_42_DH_DERIVE            = 0x00000031;
    public static final int CKM_X9_42_DH_HYBRID_DERIVE     = 0x00000032;
    public static final int CKM_X9_42_MQV_DERIVE           = 0x00000033;
    
    public static final int CKM_SHA256_RSA_PKCS            = 0x00000040;
    public static final int CKM_SHA384_RSA_PKCS            = 0x00000041;
    public static final int CKM_SHA512_RSA_PKCS            = 0x00000042;
    public static final int CKM_SHA256_RSA_PKCS_PSS        = 0x00000043;
    public static final int CKM_SHA384_RSA_PKCS_PSS        = 0x00000044;
    public static final int CKM_SHA512_RSA_PKCS_PSS        = 0x00000045;

    public static final int CKM_RC2_KEY_GEN                = 0x00000100;
    public static final int CKM_RC2_ECB                    = 0x00000101;
    public static final int CKM_RC2_CBC                    = 0x00000102;
    public static final int CKM_RC2_MAC                    = 0x00000103;
    
    /* CKM_RC2_MAC_GENERAL and CKM_RC2_CBC_PAD are new for v2.0 */
    public static final int CKM_RC2_MAC_GENERAL            = 0x00000104;
    public static final int CKM_RC2_CBC_PAD                = 0x00000105;
    
    public static final int CKM_RC4_KEY_GEN                = 0x00000110;
    public static final int CKM_RC4                        = 0x00000111;
    public static final int CKM_DES_KEY_GEN                = 0x00000120;
    public static final int CKM_DES_ECB                    = 0x00000121;
    public static final int CKM_DES_CBC                    = 0x00000122;
    public static final int CKM_DES_MAC                    = 0x00000123;
    
    /* CKM_DES_MAC_GENERAL and CKM_DES_CBC_PAD are new for v2.0 */
    public static final int CKM_DES_MAC_GENERAL            = 0x00000124;
    public static final int CKM_DES_CBC_PAD                = 0x00000125;
    
    public static final int CKM_DES2_KEY_GEN               = 0x00000130;
    public static final int CKM_DES3_KEY_GEN               = 0x00000131;
    public static final int CKM_DES3_ECB                   = 0x00000132;
    public static final int CKM_DES3_CBC                   = 0x00000133;
    public static final int CKM_DES3_MAC                   = 0x00000134;
    
    /* CKM_DES3_MAC_GENERAL, CKM_DES3_CBC_PAD, CKM_CDMF_KEY_GEN,
     * CKM_CDMF_ECB, CKM_CDMF_CBC, CKM_CDMF_MAC,
     * CKM_CDMF_MAC_GENERAL, and CKM_CDMF_CBC_PAD are new for v2.0 */
    public static final int CKM_DES3_MAC_GENERAL           = 0x00000135;
    public static final int CKM_DES3_CBC_PAD               = 0x00000136;
    public static final int CKM_CDMF_KEY_GEN               = 0x00000140;
    public static final int CKM_CDMF_ECB                   = 0x00000141;
    public static final int CKM_CDMF_CBC                   = 0x00000142;
    public static final int CKM_CDMF_MAC                   = 0x00000143;
    public static final int CKM_CDMF_MAC_GENERAL           = 0x00000144;
    public static final int CKM_CDMF_CBC_PAD               = 0x00000145;
    
    public static final int CKM_MD2                        = 0x00000200;
    
    /* CKM_MD2_HMAC and CKM_MD2_HMAC_GENERAL are new for v2.0 */
    public static final int CKM_MD2_HMAC                   = 0x00000201;
    public static final int CKM_MD2_HMAC_GENERAL           = 0x00000202;
    
    public static final int CKM_MD5                        = 0x00000210;
    
    /* CKM_MD5_HMAC and CKM_MD5_HMAC_GENERAL are new for v2.0 */
    public static final int CKM_MD5_HMAC                   = 0x00000211;
    public static final int CKM_MD5_HMAC_GENERAL           = 0x00000212;
    
    public static final int CKM_SHA_1                      = 0x00000220;
    
    /* CKM_SHA_1_HMAC and CKM_SHA_1_HMAC_GENERAL are new for v2.0 */
    public static final int CKM_SHA_1_HMAC                 = 0x00000221;
    public static final int CKM_SHA_1_HMAC_GENERAL         = 0x00000222;
    
    /* CKM_RIPEMD128, CKM_RIPEMD128_HMAC, 
     * CKM_RIPEMD128_HMAC_GENERAL, CKM_RIPEMD160, CKM_RIPEMD160_HMAC,
     * and CKM_RIPEMD160_HMAC_GENERAL are new for v2.10 */
    public static final int CKM_RIPEMD128                  = 0x00000230;
    public static final int CKM_RIPEMD128_HMAC             = 0x00000231;
    public static final int CKM_RIPEMD128_HMAC_GENERAL     = 0x00000232;
    public static final int CKM_RIPEMD160                  = 0x00000240;
    public static final int CKM_RIPEMD160_HMAC             = 0x00000241;
    public static final int CKM_RIPEMD160_HMAC_GENERAL     = 0x00000242;
    
    /* All of the following mechanisms are new for v2.0 */
    /* Note that CAST128 and CAST5 are the same algorithm */
    public static final int CKM_CAST_KEY_GEN               = 0x00000300;
    public static final int CKM_CAST_ECB                   = 0x00000301;
    public static final int CKM_CAST_CBC                   = 0x00000302;
    public static final int CKM_CAST_MAC                   = 0x00000303;
    public static final int CKM_CAST_MAC_GENERAL           = 0x00000304;
    public static final int CKM_CAST_CBC_PAD               = 0x00000305;
    public static final int CKM_CAST3_KEY_GEN              = 0x00000310;
    public static final int CKM_CAST3_ECB                  = 0x00000311;
    public static final int CKM_CAST3_CBC                  = 0x00000312;
    public static final int CKM_CAST3_MAC                  = 0x00000313;
    public static final int CKM_CAST3_MAC_GENERAL          = 0x00000314;
    public static final int CKM_CAST3_CBC_PAD              = 0x00000315;
    public static final int CKM_CAST5_KEY_GEN              = 0x00000320;
    public static final int CKM_CAST128_KEY_GEN            = 0x00000320;
    public static final int CKM_CAST5_ECB                  = 0x00000321;
    public static final int CKM_CAST128_ECB                = 0x00000321;
    public static final int CKM_CAST5_CBC                  = 0x00000322;
    public static final int CKM_CAST128_CBC                = 0x00000322;
    public static final int CKM_CAST5_MAC                  = 0x00000323;
    public static final int CKM_CAST128_MAC                = 0x00000323;
    public static final int CKM_CAST5_MAC_GENERAL          = 0x00000324;
    public static final int CKM_CAST128_MAC_GENERAL        = 0x00000324;
    public static final int CKM_CAST5_CBC_PAD              = 0x00000325;
    public static final int CKM_CAST128_CBC_PAD            = 0x00000325;
    public static final int CKM_RC5_KEY_GEN                = 0x00000330;
    public static final int CKM_RC5_ECB                    = 0x00000331;
    public static final int CKM_RC5_CBC                    = 0x00000332;
    public static final int CKM_RC5_MAC                    = 0x00000333;
    public static final int CKM_RC5_MAC_GENERAL            = 0x00000334;
    public static final int CKM_RC5_CBC_PAD                = 0x00000335;
    public static final int CKM_IDEA_KEY_GEN               = 0x00000340;
    public static final int CKM_IDEA_ECB                   = 0x00000341;
    public static final int CKM_IDEA_CBC                   = 0x00000342;
    public static final int CKM_IDEA_MAC                   = 0x00000343;
    public static final int CKM_IDEA_MAC_GENERAL           = 0x00000344;
    public static final int CKM_IDEA_CBC_PAD               = 0x00000345;
    public static final int CKM_GENERIC_SECRET_KEY_GEN     = 0x00000350;
    public static final int CKM_CONCATENATE_BASE_AND_KEY   = 0x00000360;
    public static final int CKM_CONCATENATE_BASE_AND_DATA  = 0x00000362;
    public static final int CKM_CONCATENATE_DATA_AND_BASE  = 0x00000363;
    public static final int CKM_XOR_BASE_AND_DATA          = 0x00000364;
    public static final int CKM_EXTRACT_KEY_FROM_KEY       = 0x00000365;
    public static final int CKM_SSL3_PRE_MASTER_KEY_GEN    = 0x00000370;
    public static final int CKM_SSL3_MASTER_KEY_DERIVE     = 0x00000371;
    public static final int CKM_SSL3_KEY_AND_MAC_DERIVE    = 0x00000372;
    
    /* CKM_SSL3_MASTER_KEY_DERIVE_DH, CKM_TLS_PRE_MASTER_KEY_GEN,
     * CKM_TLS_MASTER_KEY_DERIVE, CKM_TLS_KEY_AND_MAC_DERIVE, and
     * CKM_TLS_MASTER_KEY_DERIVE_DH are new for v2.11 */
    public static final int CKM_SSL3_MASTER_KEY_DERIVE_DH  = 0x00000373;
    public static final int CKM_TLS_PRE_MASTER_KEY_GEN     = 0x00000374;
    public static final int CKM_TLS_MASTER_KEY_DERIVE      = 0x00000375;
    public static final int CKM_TLS_KEY_AND_MAC_DERIVE     = 0x00000376;
    public static final int CKM_TLS_MASTER_KEY_DERIVE_DH   = 0x00000377;
    
    public static final int CKM_SSL3_MD5_MAC               = 0x00000380;
    public static final int CKM_SSL3_SHA1_MAC              = 0x00000381;
    public static final int CKM_MD5_KEY_DERIVATION         = 0x00000390;
    public static final int CKM_MD2_KEY_DERIVATION         = 0x00000391;
    public static final int CKM_SHA1_KEY_DERIVATION        = 0x00000392;
    public static final int CKM_PBE_MD2_DES_CBC            = 0x000003A0;
    public static final int CKM_PBE_MD5_DES_CBC            = 0x000003A1;
    public static final int CKM_PBE_MD5_CAST_CBC           = 0x000003A2;
    public static final int CKM_PBE_MD5_CAST3_CBC          = 0x000003A3;
    public static final int CKM_PBE_MD5_CAST5_CBC          = 0x000003A4;
    public static final int CKM_PBE_MD5_CAST128_CBC        = 0x000003A4;
    public static final int CKM_PBE_SHA1_CAST5_CBC         = 0x000003A5;
    public static final int CKM_PBE_SHA1_CAST128_CBC       = 0x000003A5;
    public static final int CKM_PBE_SHA1_RC4_128           = 0x000003A6;
    public static final int CKM_PBE_SHA1_RC4_40            = 0x000003A7;
    public static final int CKM_PBE_SHA1_DES3_EDE_CBC      = 0x000003A8;
    public static final int CKM_PBE_SHA1_DES2_EDE_CBC      = 0x000003A9;
    public static final int CKM_PBE_SHA1_RC2_128_CBC       = 0x000003AA;
    public static final int CKM_PBE_SHA1_RC2_40_CBC        = 0x000003AB;
    
    /* CKM_PKCS5_PBKD2 is new for v2.10 */
    public static final int CKM_PKCS5_PBKD2                = 0x000003B0;
    
    public static final int CKM_PBA_SHA1_WITH_SHA1_HMAC    = 0x000003C0;
    public static final int CKM_KEY_WRAP_LYNKS             = 0x00000400;
    public static final int CKM_KEY_WRAP_SET_OAEP          = 0x00000401;
    
    /* Fortezza mechanisms */
    public static final int CKM_SKIPJACK_KEY_GEN           = 0x00001000;
    public static final int CKM_SKIPJACK_ECB64             = 0x00001001;
    public static final int CKM_SKIPJACK_CBC64             = 0x00001002;
    public static final int CKM_SKIPJACK_OFB64             = 0x00001003;
    public static final int CKM_SKIPJACK_CFB64             = 0x00001004;
    public static final int CKM_SKIPJACK_CFB32             = 0x00001005;
    public static final int CKM_SKIPJACK_CFB16             = 0x00001006;
    public static final int CKM_SKIPJACK_CFB8              = 0x00001007;
    public static final int CKM_SKIPJACK_WRAP              = 0x00001008;
    public static final int CKM_SKIPJACK_PRIVATE_WRAP      = 0x00001009;
    public static final int CKM_SKIPJACK_RELAYX            = 0x0000100a;
    public static final int CKM_KEA_KEY_PAIR_GEN           = 0x00001010;
    public static final int CKM_KEA_KEY_DERIVE             = 0x00001011;
    public static final int CKM_FORTEZZA_TIMESTAMP         = 0x00001020;
    public static final int CKM_BATON_KEY_GEN              = 0x00001030;
    public static final int CKM_BATON_ECB128               = 0x00001031;
    public static final int CKM_BATON_ECB96                = 0x00001032;
    public static final int CKM_BATON_CBC128               = 0x00001033;
    public static final int CKM_BATON_COUNTER              = 0x00001034;
    public static final int CKM_BATON_SHUFFLE              = 0x00001035;
    public static final int CKM_BATON_WRAP                 = 0x00001036;
    
    /* CKM_ECDSA_KEY_PAIR_GEN is deprecated in v2.11,
     * CKM_EC_KEY_PAIR_GEN is preferred */
    public static final int CKM_ECDSA_KEY_PAIR_GEN         = 0x00001040;
    public static final int CKM_EC_KEY_PAIR_GEN            = 0x00001040;
    
    public static final int CKM_ECDSA                      = 0x00001041;
    public static final int CKM_ECDSA_SHA1                 = 0x00001042;
    
    /* CKM_ECDH1_DERIVE, CKM_ECDH1_COFACTOR_DERIVE, and CKM_ECMQV_DERIVE
     * are new for v2.11 */
    public static final int CKM_ECDH1_DERIVE               = 0x00001050;
    public static final int CKM_ECDH1_COFACTOR_DERIVE      = 0x00001051;
    public static final int CKM_ECMQV_DERIVE               = 0x00001052;
    
    public static final int CKM_JUNIPER_KEY_GEN            = 0x00001060;
    public static final int CKM_JUNIPER_ECB128             = 0x00001061;
    public static final int CKM_JUNIPER_CBC128             = 0x00001062;
    public static final int CKM_JUNIPER_COUNTER            = 0x00001063;
    public static final int CKM_JUNIPER_SHUFFLE            = 0x00001064;
    public static final int CKM_JUNIPER_WRAP               = 0x00001065;
    public static final int CKM_FASTHASH                   = 0x00001070;
    
    /* CKM_AES_KEY_GEN, CKM_AES_ECB, CKM_AES_CBC, CKM_AES_MAC,
     * CKM_AES_MAC_GENERAL, CKM_AES_CBC_PAD, CKM_DSA_PARAMETER_GEN,
     * CKM_DH_PKCS_PARAMETER_GEN, and CKM_X9_42_DH_PARAMETER_GEN are
     * new for v2.11 */
    public static final int CKM_AES_KEY_GEN                = 0x00001080;
    public static final int CKM_AES_ECB                    = 0x00001081;
    public static final int CKM_AES_CBC                    = 0x00001082;
    public static final int CKM_AES_MAC                    = 0x00001083;
    public static final int CKM_AES_MAC_GENERAL            = 0x00001084;
    public static final int CKM_AES_CBC_PAD                = 0x00001085;
    public static final int CKM_DSA_PARAMETER_GEN          = 0x00002000;
    public static final int CKM_DH_PKCS_PARAMETER_GEN      = 0x00002001;
    public static final int CKM_X9_42_DH_PARAMETER_GEN     = 0x00002002;

    private final int reference;
    private final int algorithm;
    private String algId;
    private Integer algReference;
    
    /**
     * Protected constructor.
     * 
     * @param id
     */
    protected AlgorithmInfo(int reference, int algorithm)
    {
        this.reference = reference;
        this.algorithm= algorithm;
        this.algId = null;
        this.algReference = null;
    }
    
    /**
     * @param o An ASN.1 object to decode.
     * @return A KeyIdentifier instance.
     */
    public static AlgorithmInfo getInstance(Object obj)
    {
        if (obj instanceof AlgorithmInfo)
            return (AlgorithmInfo) obj;
            
        if (obj instanceof ASN1Sequence)
        {
            ASN1Sequence seq = (ASN1Sequence)obj;
            
            Enumeration<Object> objs = seq.getObjects();
            
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("Missing id member in AlgorithmInfo SEQUENCE.");
            
            int reference = IntegerHelper.intValue(DERInteger.getInstance(objs.nextElement()).getValue());
            
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("Missing value member in AlgorithmInfo SEQUENCE.");
            
            int algorithm = IntegerHelper.intValue(DERInteger.getInstance(objs.nextElement()).getValue());
            
            AlgorithmInfo ret = null;
            
            switch (algorithm)
            {
            // all algorithms with NULL parameters.
            case nullAlgorithmId:
            case CKM_RSA_9796:
            case CKM_RSA_PKCS:
            case CKM_RSA_PKCS_KEY_PAIR_GEN:
            case CKM_RSA_PKCS_OAEP:
            case CKM_RSA_PKCS_PSS:
            case CKM_RSA_X9_31:
            case CKM_RSA_X9_31_KEY_PAIR_GEN:
            case CKM_RSA_X_509:
                ret = new NullAlgorithmInfo(reference,algorithm,
                        NullKeyInfoImpl.getInstanceFromSequence(objs));
                break;
                
            // to be continued...
                
            default:
                throw new IllegalArgumentException("Unsupported alogrithm ["+algorithm+"] in AlgorithmInfo SEQUENCE.");
            }
            
            if (!objs.hasMoreElements()) return ret;
            
            Object o = objs.nextElement();
            
            if (o instanceof DERObjectIdentifier)
            {
                ret.setAlgId(((DERObjectIdentifier)o).getId());
                
                if (!objs.hasMoreElements()) return ret;
                
                o = objs.nextElement();
            }
            
            if (o instanceof DERInteger)
            {
                ret.setAlgReference(IntegerHelper.toInteger(((DERInteger)o).getValue()));
                return ret;
            }
            
            throw new IllegalArgumentException("Illegal member ["+o+"] in AlgorithmInfo SEQUENCE.");
        }
        
        throw new IllegalArgumentException("AlgorithmInfo must be encoded as an ASN.1 SEQUENCE.");
    }
    
    /**
     * @return The algorithm-specific KeyInfo, which carries the
     *         <code>parameters</code> and <code>supportedOperations</code> fields
     *         of the ASN.1 SEQUENCE.
     */
    public abstract KeyInfoImpl<? extends DEREncodable,Operations> getKeyInfo();
    
    
    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
     */
    @Override
    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
    
        v.add(new DERInteger(this.reference));
        v.add(new DERInteger(this.algorithm));
        
        if (this.getKeyInfo() != null) {
            
            if (this.getKeyInfo().getParameters() != null)
                v.add(this.getKeyInfo().getParameters());
            
            if (this.getKeyInfo().getSupportedOperations() != null)
                v.add(this.getKeyInfo().getSupportedOperations());
        }
        
        if (this.algId != null)
            v.add(new DERObjectIdentifier(this.algId));
            
        if (this.algReference != null)
            v.add(new DERInteger(this.algReference.intValue()));
        
        return new DERSequence(v);
    }

    /**
     * @return the algId
     */
    public String getAlgId() {
        return this.algId;
    }

    /**
     * @param algId the algId to set
     */
    public void setAlgId(String algId) {
        this.algId = algId;
    }

    /**
     * @return the algReference
     */
    public Integer getAlgReference() {
        return this.algReference;
    }

    /**
     * @param algReference the algReference to set
     */
    public void setAlgReference(Integer algReference) {
        this.algReference = algReference;
    }

    /**
     * @return the reference
     */
    public int getReference() {
        return this.reference;
    }

    /**
     * @return the algorithm
     */
    public int getAlgorithm() {
        return this.algorithm;
    }

}
