import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { RendezVousService } from '../../services/rendez-vous.service';
import { AlertController } from '@ionic/angular';

@Component({
  selector: 'app-medecin-detail',
  templateUrl: './medecin-detail.page.html',
  styleUrls: ['./medecin-detail.page.scss'],
  standalone: false,
})
export class MedecinDetailPage implements OnInit {
  medecin: any = null;
  userRole: string = '';
  validDays = ['lundi', 'mardi', 'mercredi', 'jeudi', 'vendredi', 'samedi'];

  constructor(
    private route: ActivatedRoute,
    private rdvService: RendezVousService,
    private authService: AuthService,
    private alertCtrl: AlertController
  ) {}

  ngOnInit(): void {
    const medecinId = this.route.snapshot.paramMap.get('id');
    if (medecinId) {
      this.loadMedecin(medecinId);
    }
    const user = this.authService.getUser();
    this.userRole = user?.role || '';
  }

  loadMedecin(medecinId: string) {
    this.rdvService.getMedecins().subscribe({
      next: (data: any[]) => {
        this.medecin = data.find(m => m.id === medecinId);
        if (!this.medecin) {
          this.showAlert('Erreur', 'Médecin non trouvé.');
        }
      },
      error: (err) => {
        console.error('Erreur lors du chargement du médecin:', err);
        this.showAlert('Erreur', 'Impossible de charger les détails du médecin.');
      }
    });
  }

  async prendreRendezVous(medecinId: string) {
    if (!this.authService.getUser() || this.userRole !== 'patient') {
      const alert = await this.alertCtrl.create({
        header: 'Erreur',
        message: 'Vous devez être connecté en tant que patient pour prendre un rendez-vous.',
        buttons: ['OK']
      });
      await alert.present();
      return;
    }

    if (!this.medecin) {
      const alert = await this.alertCtrl.create({
        header: 'Erreur',
        message: 'Médecin non trouvé.',
        buttons: ['OK']
      });
      await alert.present();
      return;
    }

    const joursDisponibles = Object.keys(this.medecin.disponibilites).filter(
      jour => this.validDays.includes(jour) && this.medecin.disponibilites[jour]?.length > 0
    );

    if (joursDisponibles.length === 0) {
      const alert = await this.alertCtrl.create({
        header: 'Erreur',
        message: 'Aucune disponibilité pour ce médecin.',
        buttons: ['OK']
      });
      await alert.present();
      return;
    }

    const jourAlert = await this.alertCtrl.create({
      header: 'Choisir un jour',
      inputs: joursDisponibles.map(jour => ({
        name: 'jour',
        type: 'radio',
        label: jour.charAt(0).toUpperCase() + jour.slice(1),
        value: jour
      })),
      buttons: [
        { text: 'Annuler', role: 'cancel' },
        {
          text: 'Suivant',
          handler: async (selectedJour: string) => {
            if (!selectedJour) {
              const errorAlert = await this.alertCtrl.create({
                header: 'Erreur',
                message: 'Veuillez sélectionner un jour.',
                buttons: ['OK']
              });
              await errorAlert.present();
              return false;
            }

            const creneaux = this.medecin.disponibilites[selectedJour] || [];
            const creneauxValides = creneaux.filter(
              (creneau: any) => creneau.debut && creneau.fin && /^\d{1,2}:\d{2}$/.test(creneau.debut) && /^\d{1,2}:\d{2}$/.test(creneau.fin)
            );

            if (creneauxValides.length === 0) {
              const errorAlert = await this.alertCtrl.create({
                header: 'Erreur',
                message: `Aucun créneau valide disponible pour ${selectedJour}.`,
                buttons: ['OK']
              });
              await errorAlert.present();
              return false;
            }

            const creneauAlert = await this.alertCtrl.create({
              header: `Créneaux pour ${selectedJour.charAt(0).toUpperCase() + selectedJour.slice(1)}`,
              inputs: creneauxValides.map((creneau: any) => ({
                name: 'creneau',
                type: 'radio',
                label: `${creneau.debut} - ${creneau.fin}`,
                value: `${creneau.debut}|${creneau.fin}`
              })),
              buttons: [
                { text: 'Annuler', role: 'cancel' },
                {
                  text: 'Confirmer',
                  handler: async (selectedCreneau: string) => {
                    if (!selectedCreneau) {
                      const errorAlert = await this.alertCtrl.create({
                        header: 'Erreur',
                        message: 'Veuillez sélectionner un créneau.',
                        buttons: ['OK']
                      });
                      await errorAlert.present();
                      return false;
                    }

                    const [debut, fin] = selectedCreneau.split('|');
                    const rdv = {
                      medecinId: medecinId,
                      jour: selectedJour.toLowerCase(),
                      debut,
                      fin
                    };

                    this.rdvService.prendreRendezVous(rdv).subscribe({
                      next: async () => {
                        const successAlert = await this.alertCtrl.create({
                          header: 'Succès',
                          message: 'Rendez-vous pris avec succès !',
                          buttons: ['OK']
                        });
                        await successAlert.present();
                      },
                      error: async (err: any) => {
                        console.error('Erreur lors de la prise de rendez-vous:', err);
                        const errorAlert = await this.alertCtrl.create({
                          header: 'Erreur',
                          message: err.error?.message || 'Erreur lors de la prise de rendez-vous.',
                          buttons: ['OK']
                        });
                        await errorAlert.present();
                      }
                    });
                    return true;
                  }
                }
              ]
            });
            await creneauAlert.present();
            return true;
          }
        }
      ]
    });
    await jourAlert.present();
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