import { Component } from '@angular/core';
import { RendezVousService } from 'src/app/services/rendez-vous.service';
import { AlertController } from '@ionic/angular';

@Component({
    selector: 'app-espace-medecin',
    templateUrl: './espace-medecin.page.html',
    styleUrls: ['./espace-medecin.page.scss'],
    standalone: false
})
export class EspaceMedecinPage {
    jours = ['lundi', 'mardi', 'mercredi', 'jeudi', 'vendredi', 'samedi'];
    disponibilites: any = {
        lundi: [], mardi: [], mercredi: [], jeudi: [], vendredi: [], samedi: []
    };

    constructor(private rdvService: RendezVousService, private alertCtrl: AlertController) {}

    ionViewWillEnter() {
        this.rdvService.getDisponibilites().subscribe({
            next: (data) => this.disponibilites = data,
            error: (err) => console.error('Erreur:', err)
        });
    }

    async ajouterCreneau(jour: string) {
        const alert = await this.alertCtrl.create({
            header: `Ajouter un créneau pour ${jour}`,
            inputs: [
                { name: 'debut', type: 'time', placeholder: '08:00' },
                { name: 'fin', type: 'time', placeholder: '12:00' }
            ],
            buttons: [
                { text: 'Annuler', role: 'cancel' },
                {
                    text: 'Ajouter',
                    handler: (data) => {
                        if (data.debut && data.fin) {
                            this.disponibilites[jour].push({ debut: data.debut, fin: data.fin });
                            return true;
                        }
                        return false;
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
        this.rdvService.saveDisponibilites(this.disponibilites).subscribe({
            next: () => alert('Disponibilités sauvegardées'),
            error: (err) => alert('Erreur: ' + err.error.message)
        });
    }
}