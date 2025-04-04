import { Component, OnInit } from '@angular/core';
import { AuthService } from '../../services/auth.service';
import { HttpClient } from '@angular/common/http';
import { AlertController } from '@ionic/angular';


@Component({
  selector: 'app-parametres',
  templateUrl: './parametres.page.html',
  styleUrls: ['./parametres.page.scss'],
  standalone: false,
})
export class ParametresPage implements OnInit {
  user: any; // Données actuelles de l'utilisateur (depuis AuthService)
  userData: any = {}; // Données modifiables dans le formulaire
  isEditing = false;

  constructor(
    private authService: AuthService,
    private http: HttpClient,
    private alertCtrl: AlertController
  ) {}

  ngOnInit() {
    this.user = this.authService.getUser();
    console.log('Utilisateur initial depuis AuthService:', this.user);
    this.loadUserProfile();
  }

  loadUserProfile() {
    console.log('Chargement du profil...');
    this.http.get('http://127.0.0.1:5000/user/profile', {
      headers: { 'Authorization': `Bearer ${this.authService.getToken()}` }
    }).subscribe({
      next: (data: any) => {
        console.log('Données reçues du backend:', data);
        this.userData = { ...data }; // Remplir userData avec les données du backend
        this.user = { ...data }; // Synchroniser user avec les données du backend
      },
      error: (err) => {
        console.error('Erreur lors du chargement du profil:', err);
        this.showAlert('Erreur', 'Impossible de charger vos données.');
      }
    });
  }

  toggleEdit() {
    this.isEditing = !this.isEditing;
    if (!this.isEditing) {
      this.userData = { ...this.user }; // Réinitialiser userData si annulation
    }
    console.log('Mode édition:', this.isEditing, 'Données actuelles:', this.userData);
  }

  saveChanges() {
    console.log('Enregistrement des modifications:', this.userData);
    this.http.put('http://127.0.0.1:5000/user/profile', this.userData, {
      headers: { 'Authorization': `Bearer ${this.authService.getToken()}` }
    }).subscribe({
      next: () => {
        this.user = { ...this.userData }; // Mettre à jour les données locales
        this.authService.logout(); // Déconnexion pour forcer la mise à jour du token
        this.showAlert('Succès', 'Profil mis à jour. Veuillez vous reconnecter.');
      },
      error: (err) => {
        console.error('Erreur lors de la mise à jour:', err);
        this.showAlert('Erreur', 'Impossible de mettre à jour vos données.');
      }
    });
    this.isEditing = false;
  }

  async showAlert(header: string, message: string) {
    const alert = await this.alertCtrl.create({
      header,
      message,
      buttons: ['OK']
    });
    await alert.present();
  }
}