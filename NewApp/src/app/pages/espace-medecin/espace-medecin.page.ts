import { Component } from '@angular/core';
import { RendezVousService } from 'src/app/services/rendez-vous.service';
import { AlertController } from '@ionic/angular';

@Component({
  selector: 'app-espace-medecin',
  templateUrl: './espace-medecin.page.html',
  styleUrls: ['./espace-medecin.page.scss'],
  standalone: false,

})
export class EspaceMedecinPage {
  joursSemaine = ['Lundi', 'Mardi', 'Mercredi', 'Jeudi', 'Vendredi', 'Samedi'];
// Initialisez toujours la structure
disponibilites: any = {
  lundi: [], mardi: [], mercredi: [],
  jeudi: [], vendredi: [], samedi: []
};  
showDisponibilites = true;

  constructor(
    private rdvService: RendezVousService,
    private alertCtrl: AlertController
  ) {}

  ionViewWillEnter() {
    this.loadDisponibilites();
  }

  loadDisponibilites() {
    this.rdvService.getDisponibilites().subscribe({
      next: (data) => {
        // Fusion avec les valeurs par défaut
        this.disponibilites = { ...this.disponibilites, ...data };
      },
      error: (err) => {
        console.error("Erreur:", err);
        // Maintient la structure vide comme fallback
      }
    });
  }

  async ajouterCreneau(jour: string) {
    const alert = await this.alertCtrl.create({
      header: `Ajouter un créneau (${jour})`,
      inputs: [
        { name: 'debut', type: 'time', placeholder: '08:00' },
        { name: 'fin', type: 'time', placeholder: '12:00' }
      ],
      buttons: [
        { text: 'Annuler', role: 'cancel' },
        {
          text: 'Valider',
          handler: (data) => {
            if (data.debut && data.fin) {
              if (!this.disponibilites[jour]) {
                this.disponibilites[jour] = [];
              }
              this.disponibilites[jour].push({
                debut: data.debut,
                fin: data.fin
              });
            }
          }
        }
      ]
    });
    await alert.present();
  }

  supprimerCreneau(jour: string, index: number) {
    this.disponibilites[jour].splice(index, 1);
  }

  saveDisponibilites() {
    this.rdvService.updateDisponibilites(this.disponibilites).subscribe({
      next: async () => {
        const alert = await this.alertCtrl.create({
          header: 'Succès',
          message: 'Disponibilités mises à jour',
          buttons: ['OK']
        });
        await alert.present();
      },
      error: (err) => this.showError('Erreur de sauvegarde', err)
    });
  }

  private async showError(title: string, error: any) {
    const alert = await this.alertCtrl.create({
      header: title,
      message: error.message || 'Une erreur est survenue',
      buttons: ['OK']
    });
    await alert.present();
  }
}