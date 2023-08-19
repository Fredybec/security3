import axios, { AxiosResponse } from "axios";
import { AUTH_URL } from 'layout/AppConfig.tsx';
import decode from 'jsonwebtoken/decode';

export class AuthService {

    signIn(username: string, password: string): Promise<AxiosResponse<any>> {
        return axios.post(AUTH_URL, { username, password });
    }

    signOut() {
        this.removeToken();
    }

    getRoleConnectedUser(): string {
        const decodedJwt = this.decodeJWT();
        console.log(decodedJwt['roles'][0])
        return decodedJwt ? decodedJwt['roles'][0]: [];
    }

    saveToken(token: string) {
        localStorage.setItem('token', token);
    }


    removeToken() {
        localStorage.removeItem('token');
    }

    getToken() {
        return localStorage.getItem('token')
    }

    decodeJWT() {
        const token = this.getToken();

        if (token) {
            try {
                const decodedToken = decode(token.replace('Bearer ', ''));
                return decodedToken;

            } catch (error) {
                console.error('Error decoding JWT:', error);
                return null;
            }
        }
        return null;
    }

    getUsername(): string {
        const tokenDecoded = this.decodeJWT();
        return tokenDecoded.sub;
    }

    getExpirationFromToken() {
        const tokenDecoded = this.decodeJWT();
        return tokenDecoded ? tokenDecoded.exp : 0;
    }

    isTokenValid(): boolean {
        const exp = this.getExpirationFromToken();
        const now = Date.now();
        return exp * 1000 > now;
    }
};
