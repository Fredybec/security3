import {NextPageWithLayout} from 'next';
import {ReactNode} from 'react';

import DocumentTypesList from 'app/component/admin/view/referentiel-doc/document-type/list/document-type-list-admin.component';
import Layout from 'layout/layout';
import AuthGuard from 'app/component/auth/auth-guard.component';

const DocumentTypes: NextPageWithLayout = () => {
    return <DocumentTypesList />
}

DocumentTypes.getLayout = function getLayout(page: ReactNode) {
    return (
    <AuthGuard>
        <Layout>
            {page}
        </Layout>
    </AuthGuard>
    )
}

export default DocumentTypes;
