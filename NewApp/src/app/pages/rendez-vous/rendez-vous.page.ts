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

      exportToICal() {
        const icsContent = this.generateICalContent();
        const blob = new Blob([icsContent], { type: 'text/calendar' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'rendezvous.ics';
        a.click();
        window.URL.revokeObjectURL(url);
      }
    
      generateICalContent(): string {
        let ics = 'BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//MedicalApp//EN\n';
        this.rendezVous.forEach(rdv => {
          const startDate = this.getICalDate(rdv.jour, rdv.debut);
          const endDate = this.getICalDate(rdv.jour, rdv.fin);
          ics += `BEGIN:VEVENT\n`;
          ics += `UID:${rdv.id}@medicalapp.com\n`;
          ics += `DTSTART:${startDate}\n`;
          ics += `DTEND:${endDate}\n`;
          ics += `SUMMARY:Rendez-vous avec ${rdv.medecinName || 'Médecin'}\n`;
          ics += `DESCRIPTION:Statut: ${rdv.statut}\n`;
          ics += `LOCATION:${rdv.medecinAdresse || ''}\n`;
          ics += `END:VEVENT\n`;
        });
        ics += 'END:VCALENDAR';
        return ics;
      }
    
      getICalDate(jour: string, time: string): string {
        const dayMap: { [key: string]: number } = {
          lundi: 0,
          mardi: 1,
          mercredi: 2,
          jeudi: 3,
          vendredi: 4,
          samedi: 5
        };
      
        const today = new Date();
        const targetDay = dayMap[jour.toLowerCase()];
        const daysUntil = (targetDay - today.getDay() + 7) % 7 || 7;
      
        const date = new Date(today);
        date.setDate(today.getDate() + daysUntil);
      
        const [hours, minutes] = time.split(':').map(Number);
        date.setHours(hours, minutes, 0, 0);
      
        return date.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
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