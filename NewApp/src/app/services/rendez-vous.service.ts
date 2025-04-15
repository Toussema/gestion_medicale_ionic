import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { AuthService } from './auth.service';

@Injectable({ providedIn: 'root' })
export class RendezVousService {
    private apiUrl = 'http://127.0.0.1:5000';

    constructor(private http: HttpClient, private authService: AuthService) {}

    private getHeaders(): HttpHeaders {
        return new HttpHeaders({ 'Authorization': `Bearer ${this.authService.getToken()}` });
    }

    getDisponibilites(): Observable<any> {
        return this.http.get(`${this.apiUrl}/disponibilites`, { headers: this.getHeaders() });
    }

    saveDisponibilites(horaires: any): Observable<any> {
        return this.http.post(`${this.apiUrl}/disponibilites`, horaires, { headers: this.getHeaders() });
    }

    getRendezVous(): Observable<any[]> {
        return this.http.get<any[]>(`${this.apiUrl}/rendezvous`, { headers: this.getHeaders() });
    }

    prendreRendezVous(rdv: any): Observable<any> {
        return this.http.post(`${this.apiUrl}/rendezvous`, rdv, { headers: this.getHeaders() });
    }

    annulerRendezVous(rdvId: string): Observable<any> {
        return this.http.post(`${this.apiUrl}/rendezvous/${rdvId}/annuler`, {}, { headers: this.getHeaders() });
    }


    // Nouvelle méthode pour récupérer la liste des médecins
    getMedecins(): Observable<any[]> {
      return this.http.get<any[]>(`${this.apiUrl}/medecins`);  // Pas besoin de token pour cette route publique
  }

  // Nouvelle méthode pour la recherche filtrée
  searchMedecins(params: { specialite?: string, adresse?: string, term?: string }): Observable<any[]> {
    return this.http.get<any[]>(`${this.apiUrl}/medecins/search`, { params });
  }
}