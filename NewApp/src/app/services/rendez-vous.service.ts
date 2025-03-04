import { Injectable } from '@angular/core';

import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { AuthService } from './auth.service'; // Importez AuthService pour récupérer le token


@Injectable({
  providedIn: 'root',
})
export class RendezVousService {
  private apiUrl = 'http://127.0.0.1:5000'; // URL de votre API Flask

  constructor(private http: HttpClient, private authService: AuthService) {}

  /**
   * Récupère les rendez-vous d'un patient.
   */
  getRendezVousByPatient(patientId: string): Observable<any> {
    const token = this.authService.getToken(); // Récupérer le token JWT
    const headers = new HttpHeaders().set('Authorization', `Bearer ${token}`);
    return this.http.get(`${this.apiUrl}/rendezvous/patient`,{headers});
  }

  /**
   * Crée un nouveau rendez-vous.
   */
  createRendezVous(rendezVous: any): Observable<any> {
    const token = this.authService.getToken(); // Récupérer le token JWT
    const headers = new HttpHeaders().set('Authorization', `Bearer ${token}`); // Ajouter le token dans l'en-tête
    return this.http.post(`${this.apiUrl}/rendezvous`, rendezVous, { headers });
  }
}