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
 * Created: 29.12.2007
 *
 ***********************************************************/

package org.opensc.pkcs15.token.impl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.smartcardio.ATR;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensc.pkcs15.PKCS15CardException;
import org.opensc.pkcs15.PKCS15Exception;
import org.opensc.pkcs15.script.Command;
import org.opensc.pkcs15.script.ScriptParser;
import org.opensc.pkcs15.script.ScriptParserFactory;
import org.opensc.pkcs15.script.ScriptResource;
import org.opensc.pkcs15.script.ScriptResourceFactory;
import org.opensc.pkcs15.token.DF;
import org.opensc.pkcs15.token.DFAcl;
import org.opensc.pkcs15.token.EF;
import org.opensc.pkcs15.token.EFAcl;
import org.opensc.pkcs15.token.MF;
import org.opensc.pkcs15.token.PathHelper;
import org.opensc.pkcs15.token.Token;
import org.opensc.pkcs15.token.TokenFile;
import org.opensc.pkcs15.token.TokenFileAcl;
import org.opensc.pkcs15.token.TokenPath;
import org.opensc.pkcs15.util.Util;

/**
 * A token  implementation for Siemens CardOS 4.3b tokens.
 *
 * @author wglas
 */
public class CardOSToken implements Token {

    private static final Log log = LogFactory.getLog(CardOSToken.class);

    public static final ATR CARDOS_4_3_b_ATR =
        new ATR(new byte[] {
                0x3B, (byte) 0xF2, 0x18, 0x00,
                0x02, (byte) 0xC1, 0x0A, 0x31,
                (byte) 0xFE, 0x58, (byte) 0xC8, 0x08, 0x74
                });

    private static final int DEFAULT_LE = 252;
    private static final int DEFAULT_EXTENDED_LE = 65532;

    private static final String DEFAULT_RESET_RESOURCE = "classpath:org/opensc/pkcs15/scripts/cardos/v43b_reset.ser";
    private static final String RESET_SCRIPT_PROPERTY = "org.opensc.pkcs15.scripts.cardos.v43b_reset";

    private CardChannel channel;
    private TokenFile currentFile;

    /**
     * @param channel The card channel to use.
     */
    public CardOSToken(CardChannel channel) {
        super();
        this.channel = channel;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.token.Token#reset()
     */
    @Override
    public void reset() throws IOException {

        String res = System.getProperty(RESET_SCRIPT_PROPERTY);

        if (res == null)
            res = DEFAULT_RESET_RESOURCE;

        ScriptResourceFactory scriptResourceFactory = ScriptResourceFactory.getInstance();
        ScriptResource r = scriptResourceFactory.getScriptResource(res);

        ScriptParserFactory scriptParserFactory = ScriptParserFactory.getInstance();
        ScriptParser parser = scriptParserFactory.getScriptParser(res.substring(res.lastIndexOf('.')+1));

        Command cmd = parser.parseScript(r);

        try {
            while (cmd != null) {
                cmd = cmd.execute(this.channel);
            }
        } catch (CardException e) {
            throw new PKCS15CardException("Error executing reset script ["+res+"].",e);
        }
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.token.Token#close()
     */
    @Override
    public void close() throws IOException {
        try {
            this.channel.close();
        } catch (CardException e) {
            throw new PKCS15CardException("Error closing card",e);
        }
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.token.Token#createDF(int, org.opensc.pkcs15.token.DFAcl)
     */
    @Override
    public DF createDF(int path, long size, DFAcl acl) throws IOException {

        if (size < 0 || size > 65535L)
            throw new PKCS15Exception("Illegal size ["+size+"] for DF ["+PathHelper.formatPathAppend(this.currentFile.getPath(),path)+"].",PKCS15Exception.ERROR_INVALID_PARAMETER);

        ByteArrayOutputStream bos = new ByteArrayOutputStream(256);
        DataOutputStream dos = new DataOutputStream(bos);

        dos.write(0x62);
        // length of subsequent FCP data field, to be filled at end.
        dos.write(0x00);

        // fill in FCP data
        //  DF body size
        dos.write(0x81);
        dos.write(0x02);
        dos.writeShort((int)size);

        // File descriptor: 38h DF
        dos.write(0x82);
        dos.write(0x01);
        dos.write(0x38);

        // File ID
        dos.write(0x83);
        dos.write(0x02);
        dos.writeShort(path);

        // Default file status.
        dos.write(0x85);
        dos.write(0x01);
        dos.write(0x00);

        // ACL definitions
        dos.write(0x86);
        dos.write(0x08);
        dos.write(acl.getAcLifeCycle());
        dos.write(acl.getAcUpdate());
        dos.write(acl.getAcAppend());
        dos.write(acl.getAcDeactivate());
        dos.write(acl.getAcActivate());
        dos.write(acl.getAcDelete());
        dos.write(acl.getAcAdmin());
        dos.write(acl.getAcCreate());

        // get command data.
        dos.flush();
        byte [] data = bos.toByteArray();

        // fill in length of subsequent FCP data field, to be filled at end.
        data[1] = (byte)(data.length - 2);

        // CREATE FILE, P1=0x00, P2=0x00, ID -> read current EF from position 0.
        CommandAPDU cmd = new CommandAPDU(0x00,0xE0,0x00,0x00,data,DEFAULT_LE);

        try {
            ResponseAPDU resp = this.channel.transmit(cmd);

            if (resp.getSW() != PKCS15Exception.ERROR_OK)
                throw new PKCS15Exception("CREATE FILE for DF ["+PathHelper.formatPathAppend(this.currentFile.getPath(),path)+"] returned error",resp.getSW());

        } catch (CardException e) {
            throw new PKCS15CardException("Error sending CREATE FILE for DF ["+PathHelper.formatPathAppend(this.currentFile.getPath(),path)+"]",e);
        }

        return new DF(new TokenPath(this.currentFile.getPath(),path),size,acl);
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.token.Token#createEF(int, org.opensc.pkcs15.token.EFAcl)
     */
    @Override
    public EF createEF(int path, long size, EFAcl acl) throws IOException {

        if (size < 0 || size > 65535L)
            throw new PKCS15Exception("Illegal size ["+size+"] for EF ["+PathHelper.formatPathAppend(this.currentFile.getPath(),path)+"].",PKCS15Exception.ERROR_INVALID_PARAMETER);

        ByteArrayOutputStream bos = new ByteArrayOutputStream(256);
        DataOutputStream dos = new DataOutputStream(bos);

        dos.write(0x62);
        // length of subsequent FCP data field, to be filled at end.
        dos.write(0x00);

        // *** fill in FCP data
        //   Only EF:      Net size in bytes
        dos.write(0x80);
        dos.write(0x02);
        dos.writeShort((int)size);

        // File descriptor: 01h BINARY
        dos.write(0x82);
        dos.write(0x01);
        dos.write(0x01);

        // File ID
        dos.write(0x83);
        dos.write(0x02);
        dos.writeShort(path);

        // Default file status.
        dos.write(0x85);
        dos.write(0x01);
        dos.write(0x00);

        // ACL definitions
        dos.write(0x86);
        dos.write(0x09);
        dos.write(acl.getAcRead());
        dos.write(acl.getAcUpdate());
        dos.write(acl.getAcAppend());
        dos.write(acl.getAcDeactivate());
        dos.write(acl.getAcActivate());
        dos.write(acl.getAcDelete());
        dos.write(acl.getAcAdmin());
        dos.write(acl.getAcIncrease());
        dos.write(acl.getAcDecrease());

        // *** get command data.
        dos.flush();
        byte [] data = bos.toByteArray();

        // fill in length of subsequent FCP data field, to be filled at end.
        data[1] = (byte)(data.length - 2);

        // CREATE FILE, P1=0x00, P2=0x00, ID -> read current EF from position 0.
        CommandAPDU cmd = new CommandAPDU(0x00,0xE0,0x00,0x00,data,DEFAULT_LE);

        try {
            ResponseAPDU resp = this.channel.transmit(cmd);

            if (resp.getSW() != PKCS15Exception.ERROR_OK)
                throw new PKCS15Exception("CREATE FILE for EF ["+PathHelper.formatPathAppend(this.currentFile.getPath(),path)+"] returned error",resp.getSW());

        } catch (CardException e) {
            throw new PKCS15CardException("Error sending CREATE FILE for EF ["+PathHelper.formatPathAppend(this.currentFile.getPath(),path)+"]",e);
        }

        return new EF(new TokenPath(this.currentFile.getPath(),path),size,acl);
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.token.Token#deleteDF(int)
     */
    @Override
    public void deleteDF(int path) throws IOException {

        // DELETE FILE, P1=0x00, P2=0x00, ID -> read current EF from position 0.
        CommandAPDU cmd = new CommandAPDU(0x00,0xE4,0x00,0x00,PathHelper.idToPath(path),DEFAULT_LE);

        try {
            ResponseAPDU resp = this.channel.transmit(cmd);

            if (resp.getSW() != PKCS15Exception.ERROR_OK)
                throw new PKCS15Exception("DELETE FILE for DF ["+PathHelper.formatPathAppend(this.currentFile.getPath(),path)+"] returned error",resp.getSW());

        } catch (CardException e) {
            throw new PKCS15CardException("Error sending DELETE FILE for DF ["+PathHelper.formatPathAppend(this.currentFile.getPath(),path)+"]",e);
        }
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.token.Token#deleteEF(int)
     */
    @Override
    public void deleteEF(int path) throws IOException {

        // DELETE FILE, P1=0x00, P2=0x00, ID -> read current EF from position 0.
        CommandAPDU cmd = new CommandAPDU(0x00,0xE4,0x00,0x00,PathHelper.idToPath(path),DEFAULT_LE);

        try {
            ResponseAPDU resp = this.channel.transmit(cmd);

            if (resp.getSW() != PKCS15Exception.ERROR_OK)
                throw new PKCS15Exception("DELETE FILE for EF ["+PathHelper.formatPathAppend(this.currentFile.getPath(),path)+"] returned error",resp.getSW());

        } catch (CardException e) {
            throw new PKCS15CardException("Error sending DELETE FILE for EF ["+PathHelper.formatPathAppend(this.currentFile.getPath(),path)+"]",e);
        }
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.token.Token#getCurrentFile()
     */
    @Override
    public TokenFile getCurrentFile() throws IOException {

         return this.currentFile;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.token.Token#readEFData()
     */
    @Override
    public InputStream readEFData() throws IOException {

        if (this.currentFile == null)
            throw new IOException("No current EF selected.");

        // READ BINARY, P1=0x00, P2=0x00, ID -> read current EF from position 0.
        CommandAPDU cmd = new CommandAPDU(0x00,0xB0,0x00,0x00,DEFAULT_EXTENDED_LE);

        try {
            ResponseAPDU resp = this.channel.transmit(cmd);

            return new ByteArrayInputStream(resp.getData());

        } catch (CardException e) {
            throw new PKCS15CardException("Error sending READ BINARY",e);
        }
    }

    private DataInputStream getSelectFileData(ResponseAPDU resp) throws IOException
    {
        if (resp.getSW() != PKCS15Exception.ERROR_OK)
            throw new PKCS15Exception("Card error in response to SELECT FILE",resp.getSW());

        if (resp.getNr() < 2)
            throw new IOException("response to SELECT FILE contains less than 2 bytes.");

        int b = resp.getData()[0];

        if (b != 0x6f)
            throw new IOException("response to SELECT FILE contains no FCI data.");

        int n = ((int)resp.getData()[1]) & 0xff;

        if (n != resp.getNr()-2)
            throw new IOException("FCI dat in response to SELECT FILE contains invalid length.");

        return new DataInputStream(new ByteArrayInputStream(resp.getData(),2,n));

    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.token.Token#select(int)
     */
    @Override
    public TokenFile select(int path) throws IOException {

        if (this.currentFile == null)
            throw new IOException("No current DF selected.");

        // SELECT FILE, P1=0x00, P2=0x00, ID -> select EF or DF
        CommandAPDU cmd = new CommandAPDU(0x00,0xA4,0x00,0x00,PathHelper.idToPath(path),DEFAULT_LE);

        try {
            ResponseAPDU resp = this.channel.transmit(cmd);

            DataInputStream dis = getSelectFileData(resp);

            long bodySize = -1;
            long fileSize = -1;
            int acRead = TokenFileAcl.AC_ALWAYS;
            int acUpdate = TokenFileAcl.AC_ALWAYS;
            int acAppend = TokenFileAcl.AC_ALWAYS;
            int acDeactivate = TokenFileAcl.AC_ALWAYS;
            int acActivate = TokenFileAcl.AC_ALWAYS;
            int acDelete = TokenFileAcl.AC_ALWAYS;
            int acAdmin = TokenFileAcl.AC_ALWAYS;
            int acIncrease = TokenFileAcl.AC_ALWAYS;
            int acDecrease = TokenFileAcl.AC_ALWAYS;

            int tag;

            while ((tag=dis.read()) >= 0)
            {
                int n = dis.read();
                if (n<0) break;

                switch (tag)
                {
                case 0x80:
                    if (n!=2)
                        throw new IOException("Invalid length ["+n+"] of FCI tag 0x80.");
                    fileSize = dis.readUnsignedShort();
                    break;

                case 0x83:
                    if (n!=2)
                        throw new IOException("Invalid length ["+n+"] of FCI tag 0x83.");
                    int tpath = dis.readUnsignedShort();
                    if (tpath != path)
                        throw new IOException("File ID ["+PathHelper.formatID(tpath)+"] reported by SELECT FILE differs from requested ID ["+PathHelper.formatID(path)+"].");
                    break;

                case 0x81:
                    if (n!=2)
                        throw new IOException("Invalid length ["+n+"] of FCI tag 0x81.");
                    bodySize = dis.readUnsignedShort();
                    break;

                case 0x86:
                    if (n>=1) acRead = dis.read();
                    if (n>=2) acUpdate = dis.read();
                    if (n>=3) acAppend = dis.read();
                    if (n>=4) acDeactivate = dis.read();
                    if (n>=5) acActivate = dis.read();
                    if (n>=6) acDelete = dis.read();
                    if (n>=7) acAdmin = dis.read();
                    if (n>=8) acIncrease = dis.read();
                    if (n>=9) acDecrease = dis.read();

                    if (n!=9 && n!=8)
                        log.warn("Invalid length ["+n+"] of FCI tag 0x86 for EF.");

                    if (n>9)
                        dis.skipBytes(n-9);
                    break;

                default:
                    byte [] tmp = new byte[n];
                    dis.readFully(tmp);
                    log.warn("skipping FCI tag [0x"+Integer.toHexString(tag)+"], data ["+Util.asHex(tmp)+"].");
                }
            }

            if (fileSize >= 0)
                this.currentFile = new EF(new TokenPath(this.currentFile.getPath(),path),fileSize,
                        acRead,acUpdate,acAppend,acDeactivate,acActivate,
                        acDelete,acAdmin,acIncrease,acDecrease);
            else if (bodySize >= 0)
                this.currentFile = new DF(new TokenPath(this.currentFile.getPath(),path),bodySize,
                        acRead,acUpdate,acAppend,acDeactivate,acActivate,
                        acDelete,acAdmin,acIncrease);
            else
                throw new IOException("No 0x80 or 0x81 tag specified in order to distinguish between DF an EF.");

            return this.currentFile;

        } catch (CardException e) {
            throw new PKCS15CardException("Error sending SELECT FILE",e);
        }
    }

    private DF selectDFInternal(CommandAPDU cmd, TokenPath targetPath) throws IOException {

        try {
             ResponseAPDU resp = this.channel.transmit(cmd);

             DataInputStream dis = getSelectFileData(resp);

             long bodySize = 0;
             int acLifeCycle = TokenFileAcl.AC_ALWAYS;
             int acUpdate = TokenFileAcl.AC_ALWAYS;
             int acAppend = TokenFileAcl.AC_ALWAYS;
             int acDeactivate = TokenFileAcl.AC_ALWAYS;
             int acActivate = TokenFileAcl.AC_ALWAYS;
             int acDelete = TokenFileAcl.AC_ALWAYS;
             int acAdmin = TokenFileAcl.AC_ALWAYS;
             int acCreate = TokenFileAcl.AC_ALWAYS;

             int tag;

             while ((tag=dis.read()) >= 0)
             {
                 int n = dis.read();
                 if (n<0) break;

                 switch (tag)
                 {
                 case 0x81:
                     if (n!=2)
                         throw new IOException("Invalid length ["+n+"] of FCI tag 0x81.");
                     bodySize = dis.readUnsignedShort();
                     break;

                 case 0x83:
                     if (n!=2)
                         throw new IOException("Invalid length ["+n+"] of FCI tag 0x83.");
                     int tpath = dis.readUnsignedShort();
                     if (tpath != targetPath.getTailID())
                         throw new IOException("File ID ["+PathHelper.formatID(tpath)+"] reported by SELECT FILE differs from requested ID ["+PathHelper.formatID(targetPath.getTailID())+"].");
                     break;

                 case 0x86:
                     if (n>=1) acLifeCycle = dis.read();
                     if (n>=2) acUpdate = dis.read();
                     if (n>=3) acAppend = dis.read();
                     if (n>=4) acDeactivate = dis.read();
                     if (n>=5) acActivate = dis.read();
                     if (n>=6) acDelete = dis.read();
                     if (n>=7) acAdmin = dis.read();
                     if (n>=8) acCreate = dis.read();

                     if (n!=8)
                         log.warn("Invalid length ["+n+"] of FCI tag 0x86 for DF.");

                     if (n>8)
                         dis.skipBytes(n-8);
                     break;

                 default:
                     byte [] tmp = new byte[n];
                     dis.readFully(tmp);
                     log.warn("skipping FCI tag [0x"+Integer.toHexString(tag)+"], data ["+Util.asHex(tmp)+"].");
                 }
             }

             DF df = new DF(targetPath,bodySize,
                     acLifeCycle,acUpdate,acAppend,acDeactivate,acActivate,
                     acDelete,acAdmin,acCreate);

             this.currentFile = df;
             return df;

         } catch (CardException e) {
             throw new PKCS15CardException("Error sending select MF",e);
         }
     }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.token.Token#selectDF(int)
     */
    @Override
    public DF selectDF(int path) throws IOException {

        if (this.currentFile == null)
            throw new IOException("No current DF selected.");

        // SELECT FILE, P1=0x01, P2=0x00, no data -> select DF
        CommandAPDU cmd = new CommandAPDU(0x00,0xA4,0x01,0x00,PathHelper.idToPath(path),DEFAULT_LE);

        return this.selectDFInternal(cmd,new TokenPath(this.currentFile.getPath(),path));
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.token.Token#selectEF(int)
     */
    @Override
    public EF selectEF(int path) throws IOException {

        if (this.currentFile == null)
            throw new IOException("No current DF selected.");

        // SELECT FILE, P1=0x02, P2=0x00, no data -> select EF
        CommandAPDU cmd = new CommandAPDU(0x00,0xA4,0x02,0x00,PathHelper.idToPath(path),DEFAULT_LE);

        try {
            ResponseAPDU resp = this.channel.transmit(cmd);

            DataInputStream dis = getSelectFileData(resp);

            long fileSize = 0;
            int acRead = TokenFileAcl.AC_ALWAYS;
            int acUpdate = TokenFileAcl.AC_ALWAYS;
            int acAppend = TokenFileAcl.AC_ALWAYS;
            int acDeactivate = TokenFileAcl.AC_ALWAYS;
            int acActivate = TokenFileAcl.AC_ALWAYS;
            int acDelete = TokenFileAcl.AC_ALWAYS;
            int acAdmin = TokenFileAcl.AC_ALWAYS;
            int acIncrease = TokenFileAcl.AC_ALWAYS;
            int acDecrease = TokenFileAcl.AC_ALWAYS;

            int tag;

            while ((tag=dis.read()) >= 0)
            {
                int n = dis.read();
                if (n<0) break;

                switch (tag)
                {
                case 0x80:
                    if (n!=2)
                        throw new IOException("Invalid length ["+n+"] of FCI tag 0x80.");
                    fileSize = dis.readUnsignedShort();
                    break;

                case 0x83:
                    if (n!=2)
                        throw new IOException("Invalid length ["+n+"] of FCI tag 0x83.");
                    int tpath = dis.readUnsignedShort();
                    if (tpath != path)
                        throw new IOException("File ID ["+PathHelper.formatID(tpath)+"] reported by SELECT FILE differs from requested ID ["+PathHelper.formatID(path)+"].");
                    break;

                case 0x86:
                    if (n>=1) acRead = dis.read();
                    if (n>=2) acUpdate = dis.read();
                    if (n>=3) acAppend = dis.read();
                    if (n>=4) acDeactivate = dis.read();
                    if (n>=5) acActivate = dis.read();
                    if (n>=6) acDelete = dis.read();
                    if (n>=7) acAdmin = dis.read();
                    if (n>=8) acIncrease = dis.read();
                    if (n>=9) acDecrease = dis.read();

                    if (n!=9)
                        log.warn("Invalid length ["+n+"] of FCI tag 0x86 for EF.");

                    if (n>9)
                        dis.skipBytes(n-9);
                    break;

                default:
                    byte [] tmp = new byte[n];
                    dis.readFully(tmp);
                    log.warn("skipping FCI tag [0x"+Integer.toHexString(tag)+"], data ["+Util.asHex(tmp)+"].");
                }
            }

            EF ef = new EF(new TokenPath(this.currentFile.getPath(),path),fileSize,
                    acRead,acUpdate,acAppend,acDeactivate,acActivate,
                    acDelete,acAdmin,acIncrease,acDecrease);

            this.currentFile = ef;
            return ef;

        } catch (CardException e) {
            throw new PKCS15CardException("Error sending select MF",e);
        }
   }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.token.Token#selectMF()
     */
    @Override
    public MF selectMF() throws IOException {

        // SELECT FILE, P1=0x00, P2=0x00, no data -> select MF
        CommandAPDU cmd = new CommandAPDU(0x00,0xA4,0x00,0x00,DEFAULT_LE);

        try {
            ResponseAPDU resp = this.channel.transmit(cmd);

            DataInputStream dis = getSelectFileData(resp);

            long bodySize = 0;
            int acLifeCycle = TokenFileAcl.AC_ALWAYS;
            int acUpdate = TokenFileAcl.AC_ALWAYS;
            int acAppend = TokenFileAcl.AC_ALWAYS;
            int acDeactivate = TokenFileAcl.AC_ALWAYS;
            int acActivate = TokenFileAcl.AC_ALWAYS;
            int acDelete = TokenFileAcl.AC_ALWAYS;
            int acAdmin = TokenFileAcl.AC_ALWAYS;
            int acCreate = TokenFileAcl.AC_ALWAYS;
            int acExecute = TokenFileAcl.AC_ALWAYS;
            int acAllocate = TokenFileAcl.AC_ALWAYS;

            int tag;

            while ((tag=dis.read()) >= 0)
            {
                int n = dis.read();
                if (n<0) break;

                switch (tag)
                {
                case 0x81:
                    if (n!=2)
                        throw new IOException("Invalid length ["+n+"] of FCI tag 0x81.");
                    bodySize = dis.readUnsignedShort();
                    break;

                case 0x83:
                    if (n!=2)
                        throw new IOException("Invalid length ["+n+"] of FCI tag 0x83.");
                    int tpath = dis.readUnsignedShort();
                    if (tpath != PathHelper.MF_ID)
                        throw new IOException("File ID ["+PathHelper.formatID(tpath)+"] reported by SELECT FILE differs from requested ID ["+PathHelper.formatID(PathHelper.MF_ID)+"].");
                    break;

                case 0x86:
                    if (n>=1) acLifeCycle = dis.read();
                    if (n>=2) acUpdate = dis.read();
                    if (n>=3) acAppend = dis.read();
                    if (n>=4) acDeactivate = dis.read();
                    if (n>=5) acActivate = dis.read();
                    if (n>=6) acDelete = dis.read();
                    if (n>=7) acAdmin = dis.read();
                    if (n>=8) acCreate = dis.read();
                    if (n>=9) acExecute = dis.read();
                    if (n>=10) acAllocate = dis.read();

                    if (n!=10)
                        log.warn("Invalid length ["+n+"] of FCI tag 0x86 for MF.");

                    if (n>10)
                        dis.skipBytes(n-10);
                    break;

                default:
                    byte [] tmp = new byte[n];
                    dis.readFully(tmp);
                    log.warn("skipping FCI tag [0x"+Integer.toHexString(tag)+"], data ["+Util.asHex(tmp)+"].");
                }
            }

            MF mf = new MF(PathHelper.MF_PATH,bodySize,
                    acLifeCycle,acUpdate,acAppend,acDeactivate,acActivate,
                    acDelete,acAdmin,acCreate,acExecute,acAllocate);

            this.currentFile = mf;
            return mf;

        } catch (CardException e) {
            throw new PKCS15CardException("Error sending select MF",e);
        }
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.token.Token#selectParentDF()
     */
    @Override
    public DF selectParentDF() throws IOException {

        // SELECT FILE, P1=0x03, P2=0x00, no data -> select parent DF
        CommandAPDU cmd = new CommandAPDU(0x00,0xA4,0x03,0x00,DEFAULT_LE);

        return this.selectDFInternal(cmd,this.currentFile.getPath().getParent());
    }

    private class EFOutputStream extends ByteArrayOutputStream {

        private final TokenPath pathToWrite;
        private int lastFlushPos;

        EFOutputStream(final TokenPath pathToWrite) {
            this.pathToWrite = pathToWrite;
        }

        /* (non-Javadoc)
         * @see java.io.ByteArrayOutputStream#close()
         */
        @Override
        public void flush() throws IOException {

            if (this.size() == this.lastFlushPos) return;

            if (!this.pathToWrite.equals(CardOSToken.this.currentFile.getPath()))
                throw new PKCS15Exception("Path changed before writing content to EF ["+this.pathToWrite+"].",PKCS15Exception.ERROR_TECHNICAL_ERROR);

            super.close();

            // UPDATE BINARY, P1=0x00, P2=0x00, ID -> read current EF from position 0.
            CommandAPDU cmd = new CommandAPDU(0x00,0xD6,0x00,0x00,this.toByteArray(),DEFAULT_LE);

            try {
                ResponseAPDU resp = CardOSToken.this.channel.transmit(cmd);

                if (resp.getSW() != PKCS15Exception.ERROR_OK)
                    throw new PKCS15Exception("UPDATE BINARY for EF ["+this.pathToWrite+"] returned error",resp.getSW());

                this.lastFlushPos = this.size();

            } catch (CardException e) {
                throw new PKCS15CardException("Error sending UPDATE BINARY for EF ["+this.pathToWrite+"]",e);
            }
        }

        /* (non-Javadoc)
         * @see java.io.ByteArrayOutputStream#close()
         */
        @Override
        public void close() throws IOException {

            this.flush();
            super.close();
        }
    };

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.token.Token#writeEFData()
     */
    @Override
    public OutputStream writeEFData() throws IOException {

        if (this.currentFile == null)
            throw new IOException("No current EF selected.");

        return new EFOutputStream(this.currentFile.getPath());
    }

}
