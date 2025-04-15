import { Component } from '@angular/core';
import { RendezVousService } from 'src/app/services/rendez-vous.service';
import { AuthService } from 'src/app/services/auth.service';
import { AlertController } from '@ionic/angular';

@Component({
    selector: 'app-rendez-vous',
    templateUrl: './rendez-vous.page.html',
    styleUrls: ['./rendez-vous.page.scss'],
    standalone: false
})
export class RendezVousPage {
    rendezVous: any[] = [];
    userRole: string = '';

    constructor(private rdvService: RendezVousService, private authService: AuthService, private alertCtrl: AlertController) {}

    ionViewWillEnter() {
        const user = this.authService.getUser();
        this.userRole = user ? user.role : '';
        this.loadRendezVous();
    }

    loadRendezVous() {
        this.rdvService.getRendezVous().subscribe({
            next: (data) => this.rendezVous = data,
            error: (err) => console.error('Erreur:', err)
        });
    }

    async annulerRdv(rdvId: string) {
        const confirmAlert = await this.alertCtrl.create({
          header: 'Confirmer l’annulation',
          message: 'Êtes-vous sûr de vouloir annuler ce rendez-vous ?',
          buttons: [
            { text: 'Non', role: 'cancel' },
            {
              text: 'Oui',
              handler: () => {
                this.rdvService.annulerRendezVous(rdvId).subscribe({
                  next: async () => {
                    await this.showAlert('Succès', 'Rendez-vous annulé avec succès.');
                    this.loadRendezVous();
                  },
                  error: async (err) => {
                    console.error('Erreur lors de l’annulation:', err);
                    await this.showAlert('Erreur', err.error?.message || 'Erreur lors de l’annulation.');
                  }
                });
              }
            }
          ]
        });
        await confirmAlert.present();
      }

        // ✅ méthode manquante pour afficher une alerte simple
  async showAlert(header: string, message: string) {
    const alert = await this.alertCtrl.create({
      header,
      message,
      buttons: ['OK']
    });
    await alert.present();
  }
}