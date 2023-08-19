import {NextPageWithLayout} from 'next';
import {ReactNode} from 'react';

import TagsList from 'app/component/collaborateur/view/referentiel-doc/tag/list/tag-list-collaborateur.component';
import Layout from 'layout/layout';
import AuthGuard from 'app/component/auth/auth-guard.component';

const Tags: NextPageWithLayout = () => {
    return <TagsList />
}

Tags.getLayout = function getLayout(page: ReactNode) {
    return (
    <AuthGuard>
        <Layout>
            {page}
        </Layout>
    </AuthGuard>
    )
}

export default Tags;
