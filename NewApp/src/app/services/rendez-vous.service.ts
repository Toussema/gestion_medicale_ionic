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


  private getHeaders(): HttpHeaders {
    const token = this.authService.getToken();
    return new HttpHeaders({
      'Authorization': `Bearer ${token}`
    });
  }

  getDisponibilites(): Observable<any> {
    return this.http.get(`${this.apiUrl}/medecins/disponibilites`, {
      headers: this.getHeaders()
    });
  }
  
  updateDisponibilites(disponibilites: any): Observable<any> {
    return this.http.post(
      `${this.apiUrl}/medecins/disponibilites`,
      disponibilites,  // Envoie directement l'objet
      { headers: this.getHeaders() }
    );
  }

      // Pour tous les utilisateurs
  getRendezVous(): Observable<any[]> {
    return this.http.get<any[]>(`${this.apiUrl}/rendezvous`);
  }

  // Pour les patients
  getCreneauxDisponibles(medecinId: string, date: string): Observable<any[]> {
    return this.http.get<any[]>(`${this.apiUrl}/medecins/${medecinId}/creneaux?date=${date}`);
  }


  prendreRendezVous(rdv: any): Observable<any> {
    return this.http.post(`${this.apiUrl}/rendezvous`, rdv);
  }

  annulerRendezVous(rdvId: string): Observable<any> {
    return this.http.patch(`${this.apiUrl}/rendezvous/${rdvId}/annuler`, {});
  }


}