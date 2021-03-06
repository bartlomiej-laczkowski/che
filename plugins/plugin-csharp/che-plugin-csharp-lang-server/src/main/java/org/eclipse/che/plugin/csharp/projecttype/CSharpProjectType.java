/*******************************************************************************
 * Copyright (c) 2012-2017 Codenvy, S.A.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *   Codenvy, S.A. - initial API and implementation
 *******************************************************************************/
package org.eclipse.che.plugin.csharp.projecttype;

import com.google.inject.Inject;

import org.eclipse.che.api.project.server.type.ProjectTypeDef;
import org.eclipse.che.plugin.csharp.shared.Constants;

/**
 * C# project type
 * @author Anatolii Bazko
 */
public class CSharpProjectType extends ProjectTypeDef {
    @Inject
    public CSharpProjectType() {
        super(Constants.CSHARP_PROJECT_TYPE_ID, "C# .NET Core", true, false, true);
        addConstantDefinition(Constants.LANGUAGE, "language", Constants.CSHARP_LANG);
    }
}
