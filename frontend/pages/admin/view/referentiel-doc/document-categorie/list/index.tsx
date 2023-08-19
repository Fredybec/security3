import {NextPageWithLayout} from 'next';
import {ReactNode} from 'react';

import DocumentCategoriesList from 'app/component/admin/view/referentiel-doc/document-categorie/list/document-categorie-list-admin.component';
import Layout from 'layout/layout';
import AuthGuard from 'app/component/auth/auth-guard.component';

const DocumentCategories: NextPageWithLayout = () => {
    return <DocumentCategoriesList />
}

DocumentCategories.getLayout = function getLayout(page: ReactNode) {
    return (
    <AuthGuard>
        <Layout>
            {page}
        </Layout>
    </AuthGuard>
    )
}

export default DocumentCategories;
