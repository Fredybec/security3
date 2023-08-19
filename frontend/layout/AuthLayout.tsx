import React from 'react';

import styles from './styles.module.scss';

const AuthLayout = ({ children }: { children: React.ReactNode }): React.ReactElement => {
  return (
    <div className={styles.authLayoutContainer}>
      <div className={styles.authLayoutLeft} ></div>
      <div className={styles.authLayoutRight}>{children}</div>
    </div>
  );
};

export default AuthLayout;
