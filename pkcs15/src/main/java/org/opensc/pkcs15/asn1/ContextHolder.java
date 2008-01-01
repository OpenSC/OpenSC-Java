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
 * Created: 01.01.2008
 * 
 ***********************************************************/

package org.opensc.pkcs15.asn1;

/**
 * The static thread-local context registry.
 * 
 * @author wglas
 */
public abstract class ContextHolder {

    private static final ThreadLocal<Context> holder = new ThreadLocal<Context>();
    
    /**
     * @param context Register the given context for this thread.
     */
    public static void setContext(Context context)
    {
        holder.set(context);
    }
    
    /**
     * Remove the context from this thread.
     */
    public static void removeContext()
    {
        holder.remove();
    }
    
    /**
     * @return The thread-local context registered using {@link #setContext(Context)}.
     */
    public static Context getContext()
    {
        return holder.get();
    }    
}
