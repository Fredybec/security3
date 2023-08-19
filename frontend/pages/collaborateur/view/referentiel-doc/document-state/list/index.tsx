import {NextPageWithLayout} from 'next';
import {ReactNode} from 'react';

import DocumentStatesList from 'app/component/collaborateur/view/referentiel-doc/document-state/list/document-state-list-collaborateur.component';
import Layout from 'layout/layout';
import AuthGuard from 'app/component/auth/auth-guard.component';

const DocumentStates: NextPageWithLayout = () => {
    return <DocumentStatesList />
}

DocumentStates.getLayout = function getLayout(page: ReactNode) {
    return (
    <AuthGuard>
        <Layout>
            {page}
        </Layout>
    </AuthGuard>
    )
}

export default DocumentStates;
