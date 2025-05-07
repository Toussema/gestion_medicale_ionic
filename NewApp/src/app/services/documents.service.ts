import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders, HttpParams } from '@angular/common/http';
import { map, Observable } from 'rxjs';
import { AuthService } from './auth.service';

@Injectable({ providedIn: 'root' })
export class DocumentsService {
  private apiUrl = 'http://127.0.0.1:5000';

  constructor(private http: HttpClient, private authService: AuthService) {}

  private getHeaders(): HttpHeaders {
    return new HttpHeaders({ 'Authorization': `Bearer ${this.authService.getToken()}` });
  }

  uploadDocument(formData: FormData): Observable<any> {
    return this.http.post(`${this.apiUrl}/documents/upload`, formData, { headers: this.getHeaders() });
  }

  getPatientDocuments(): Observable<any[]> {
    return this.http.get<any[]>(`${this.apiUrl}/documents/patient`, { headers: this.getHeaders() });
  }

  getMedecinDocuments(): Observable<any[]> {
    return this.http.get<any[]>(`${this.apiUrl}/documents/medecin`, { headers: this.getHeaders() });
  }

  downloadDocument(docId: number, preview: boolean = false): Observable<Blob> {
    let params = new HttpParams();
    if (preview) {
      params = params.set('preview', 'true');
    }
    return this.http.get(`${this.apiUrl}/documents/${docId}/download`, {
      headers: this.getHeaders(),
      params: params,
      responseType: 'blob'
    });
  }

  annotateDocument(docId: number, remarques: string): Observable<any> {
    return this.http.put(`${this.apiUrl}/documents/${docId}/annotate`, { remarques }, { headers: this.getHeaders() });
  }

  // Méthode existante pour tous les médecins (gardée pour d'autres usages)
  getMedecins(): Observable<any[]> {
    return this.http.get<any[]>(`${this.apiUrl}/medecins`);
  }

  // Nouvelle méthode pour les médecins liés par rendez-vous
  getPatientMedecins(): Observable<any[]> {
    return this.http.get<any[]>(`${this.apiUrl}/patient/medecins`, { headers: this.getHeaders() });
  }

  // Méthodes pour les notifications (inchangées)
  getNotifications(): Observable<any[]> {
    return this.http.get<any[]>(`${this.apiUrl}/notifications`, { headers: this.getHeaders() });
  }

  markNotificationRead(notifId: string): Observable<any> {
    return this.http.put(`${this.apiUrl}/notifications/${notifId}/read`, {}, { headers: this.getHeaders() });
  }

  getUnreadNotificationsCount(): Observable<number> {
    return this.getNotifications().pipe(
      map(notifications => notifications.filter(n => !n.read).length)
    );
  }
}