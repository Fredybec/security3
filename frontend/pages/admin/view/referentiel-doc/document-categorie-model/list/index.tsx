import {NextPageWithLayout} from 'next';
import {ReactNode} from 'react';

import DocumentCategorieModelsList from 'app/component/admin/view/referentiel-doc/document-categorie-model/list/document-categorie-model-list-admin.component';
import Layout from 'layout/layout';
import AuthGuard from 'app/component/auth/auth-guard.component';

const DocumentCategorieModels: NextPageWithLayout = () => {
    return <DocumentCategorieModelsList />
}

DocumentCategorieModels.getLayout = function getLayout(page: ReactNode) {
    return (
    <AuthGuard>
        <Layout>
            {page}
        </Layout>
    </AuthGuard>
    )
}

export default DocumentCategorieModels;
