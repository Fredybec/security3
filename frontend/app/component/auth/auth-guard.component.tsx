import { AuthService } from 'app/zynerator/security/Auth.service';
import { useRouter } from 'next/router';
import React, { useEffect, useState } from 'react';


const AuthGuard = ({ children }) => {
    const authService = new AuthService();
    const [isTokenValid, setIsTokenValid] = useState<boolean | null>(null);
    const router = useRouter();

    useEffect(() => {
        const isTokenValid = authService.isTokenValid();
        console.log("tokenvalid ??   "+isTokenValid )
        setIsTokenValid(isTokenValid)
    }, []);

    if (isTokenValid == false) {
        router.push("/auth")
    }

    if (isTokenValid == true) {
        return children;
    }

    return <></>
};
export default AuthGuard
