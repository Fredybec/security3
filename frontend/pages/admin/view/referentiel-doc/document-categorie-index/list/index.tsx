import {NextPageWithLayout} from 'next';
import {ReactNode} from 'react';

import DocumentCategorieIndexsList from 'app/component/admin/view/referentiel-doc/document-categorie-index/list/document-categorie-index-list-admin.component';
import Layout from 'layout/layout';
import AuthGuard from 'app/component/auth/auth-guard.component';

const DocumentCategorieIndexs: NextPageWithLayout = () => {
    return <DocumentCategorieIndexsList />
}

DocumentCategorieIndexs.getLayout = function getLayout(page: ReactNode) {
    return (
    <AuthGuard>
        <Layout>
            {page}
        </Layout>
    </AuthGuard>
    )
}

export default DocumentCategorieIndexs;
