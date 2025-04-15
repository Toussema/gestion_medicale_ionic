import { Component, OnInit } from '@angular/core';
import { AuthService } from '../../services/auth.service';
import { HttpClient } from '@angular/common/http';
import { AlertController } from '@ionic/angular';
import { Router } from '@angular/router';
import { IonicModule } from '@ionic/angular';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-parametres',
  templateUrl: './parametres.page.html',
  styleUrls: ['./parametres.page.scss'],
  standalone: false,
})
export class ParametresPage implements OnInit {
  user: any = {};
  userData: any = {};
  isEditing = false;

  constructor(
    private authService: AuthService,
    private http: HttpClient,
    private alertCtrl: AlertController,
    private router: Router
  ) {}

  ngOnInit() {
    this.user = this.authService.getUser() || {};
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
        this.userData = { ...data };
        this.user = { ...data };
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
      this.userData = { ...this.user };
    }
    console.log('Mode édition:', this.isEditing, 'Données actuelles:', this.userData);
  }

  async saveChanges() {
    const alert = await this.alertCtrl.create({
      header: 'Confirmer la modification',
      message: 'Veuillez entrer votre email et mot de passe pour confirmer.',
      inputs: [
        {
          name: 'email',
          type: 'email',
          placeholder: 'Votre email'
        },
        {
          name: 'password',
          type: 'password',
          placeholder: 'Votre mot de passe'
        }
      ],
      buttons: [
        { text: 'Annuler', role: 'cancel' },
        {
          text: 'Confirmer',
          handler: (data) => {
            if (!data.email || !data.password) {
              this.showAlert('Erreur', 'Email et mot de passe requis.');
              return false;
            }

            // Ajouter email et mot de passe aux données envoyées
            const payload = {
              ...this.userData,
              email: data.email,
              password: data.password
            };

            this.http.put('http://127.0.0.1:5000/user/profile', payload, {
              headers: { 'Authorization': `Bearer ${this.authService.getToken()}` }
            }).subscribe({
              next: () => {
                this.user = { ...this.userData };
                this.authService.logout();
                this.showAlert('Succès', 'Profil mis à jour avec succès. Veuillez vous reconnecter.', () => {
                  this.router.navigate(['/login']);
                });
              },
              error: (err) => {
                console.error('Erreur lors de la mise à jour:', err);
                const message = err.error?.message || 'Erreur lors de la mise à jour. Vérifiez vos identifiants.';
                this.showAlert('Erreur', message);
              }
            });
            return true;
          }
        }
      ]
    });
    await alert.present();
    this.isEditing = false;
  }

  async deleteAccount() {
    const confirmAlert = await this.alertCtrl.create({
      header: 'Supprimer le compte',
      message: 'Êtes-vous sûr de vouloir supprimer votre compte ? Cette action est irréversible.',
      buttons: [
        { text: 'Annuler', role: 'cancel' },
        {
          text: 'Oui, supprimer',
          handler: async () => {
            const credAlert = await this.alertCtrl.create({
              header: 'Confirmer la suppression',
              message: 'Veuillez entrer votre email et mot de passe pour confirmer.',
              inputs: [
                {
                  name: 'email',
                  type: 'email',
                  placeholder: 'Votre email'
                },
                {
                  name: 'password',
                  type: 'password',
                  placeholder: 'Votre mot de passe'
                }
              ],
              buttons: [
                { text: 'Annuler', role: 'cancel' },
                {
                  text: 'Confirmer',
                  handler: (data) => {
                    if (!data.email || !data.password) {
                      this.showAlert('Erreur', 'Email et mot de passe requis.');
                      return false;
                    }

                    this.http.delete('http://127.0.0.1:5000/user/delete', {
                      headers: { 'Authorization': `Bearer ${this.authService.getToken()}` },
                      body: { email: data.email, password: data.password }
                    }).subscribe({
                      next: () => {
                        this.authService.logout();
                        this.showAlert('Succès', 'Compte supprimé avec succès.', () => {
                          this.router.navigate(['/login']);
                        });
                      },
                      error: (err) => {
                        console.error('Erreur lors de la suppression:', err);
                        const message = err.error?.message || 'Erreur lors de la suppression. Vérifiez vos identifiants.';
                        this.showAlert('Erreur', message);
                      }
                    });
                    return true;
                  }
                }
              ]
            });
            await credAlert.present();
          }
        }
      ]
    });
    await confirmAlert.present();
  }

  async showAlert(header: string, message: string, callback?: () => void) {
    const alert = await this.alertCtrl.create({
      header,
      message,
      buttons: [{
        text: 'OK',
        handler: callback
      }]
    });
    await alert.present();
  }
}