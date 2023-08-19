import {NextPageWithLayout} from 'next';
import {ReactNode} from 'react';

import GroupesList from 'app/component/admin/view/referentiel-partage/groupe/list/groupe-list-admin.component';
import Layout from 'layout/layout';
import AuthGuard from 'app/component/auth/auth-guard.component';

const Groupes: NextPageWithLayout = () => {
    return <GroupesList />
}

Groupes.getLayout = function getLayout(page: ReactNode) {
    return (
    <AuthGuard>
        <Layout>
            {page}
        </Layout>
    </AuthGuard>
    )
}

export default Groupes;
