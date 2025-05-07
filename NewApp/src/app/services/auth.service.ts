import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable } from 'rxjs';
import { Router } from '@angular/router';

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  private apiUrl = 'http://127.0.0.1:5000'; // 🚀 Backend Flask

  // BehaviorSubject pour gérer l'état de connexion et les informations de l'utilisateur
  private isLoggedInSubject = new BehaviorSubject<boolean>(this.isLoggedIn());
  isLoggedIn$ = this.isLoggedInSubject.asObservable();

  private userSubject = new BehaviorSubject<any>(this.getUser());
  user$ = this.userSubject.asObservable();

  constructor(private http: HttpClient, private router: Router) {}

  // 📌 Inscription
  register(user: any): Observable<any> {
    return this.http.post<any>(`${this.apiUrl}/register`, user);
  }

  // 📌 Connexion avec redirection selon le rôle
  login(email: string, password: string): Observable<any> {
    return new Observable((observer) => {
      this.http.post<any>(`${this.apiUrl}/login`, { email, password }).subscribe(
        (response) => {
          if (response.token && response.user) {
            this.saveToken(response.token);
            this.saveUser(response.user); // Sauvegarder l'utilisateur avec son rôle

            // Mettre à jour les BehaviorSubject
            this.isLoggedInSubject.next(true);
            this.userSubject.next(response.user);

            // Redirection après connexion
            if (response.user.role === 'patient') {
              this.router.navigate(['/espace-patient']);
            } else if (response.user.role === 'medecin') {
              this.router.navigate(['/espace-medecin']);
            } else {
              this.router.navigate(['/home']); // Redirection par défaut
            }

            observer.next(response);
            observer.complete();
          } else {
            observer.error('Authentification échouée');
          }
        },
        (error) => observer.error(error)
      );
    });
  }

  // 📌 Sauvegarde du token dans le stockage local
  saveToken(token: string): void {
    localStorage.setItem('authToken', token);
  }

  // 📌 Sauvegarde de l'utilisateur
  saveUser(user: any): void {
    localStorage.setItem('user', JSON.stringify(user));
  }

  // 📌 Récupération du token
  getToken(): string | null {
    return localStorage.getItem('authToken');
  }

  // 📌 Récupération de l'utilisateur (nom et rôle)
  getUser(): any {
    const user = localStorage.getItem('user');
    return user ? JSON.parse(user) : null;
  }

  // 📌 Vérification si l'utilisateur est connecté
  isLoggedIn(): boolean {
    return this.getToken() !== null;
  }

  // 📌 Déconnexion : suppression du token et de l'utilisateur
  logout(): void {
    localStorage.removeItem('authToken');
    localStorage.removeItem('user');

    // Mettre à jour les BehaviorSubject
    this.isLoggedInSubject.next(false);
    this.userSubject.next(null);

    this.router.navigate(['/home']); // Retour à l'accueil après déconnexion
  }

  // Nouvelle méthode pour gérer l'expiration du token
  handleUnauthorized() {
    this.logout();
  }
}