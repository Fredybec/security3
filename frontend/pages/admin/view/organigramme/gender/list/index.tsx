import {NextPageWithLayout} from 'next';
import {ReactNode} from 'react';

import GendersList from 'app/component/admin/view/organigramme/gender/list/gender-list-admin.component';
import Layout from 'layout/layout';
import AuthGuard from 'app/component/auth/auth-guard.component';

const Genders: NextPageWithLayout = () => {
    return <GendersList />
}

Genders.getLayout = function getLayout(page: ReactNode) {
    return (
    <AuthGuard>
        <Layout>
            {page}
        </Layout>
    </AuthGuard>
    )
}

export default Genders;
