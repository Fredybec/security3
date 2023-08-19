import {NextPageWithLayout} from 'next';
import {ReactNode} from 'react';

import DocumentsList from 'app/component/admin/view/doc/document/list/document-list-admin.component';
import Layout from 'layout/layout';
import AuthGuard from 'app/component/auth/auth-guard.component';

const Documents: NextPageWithLayout = () => {
    return <DocumentsList />
}

Documents.getLayout = function getLayout(page: ReactNode) {
    return (
    <AuthGuard>
        <Layout>
            {page}
        </Layout>
    </AuthGuard>
    )
}

export default Documents;
