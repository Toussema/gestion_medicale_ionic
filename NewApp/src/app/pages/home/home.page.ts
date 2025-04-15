import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { RendezVousService } from '../../services/rendez-vous.service';
import { AlertController, PopoverController } from '@ionic/angular';

@Component({
  selector: 'app-home',
  templateUrl: 'home.page.html',
  styleUrls: ['home.page.scss'],
  standalone: false,
})
export class HomePage implements OnInit {
  isLoggedIn = false;
  userName: string = '';
  userRole: string = '';
  medecins: any[] = [];
  allMedecins: any[] = [];
  validDays = ['lundi', 'mardi', 'mercredi', 'jeudi', 'vendredi', 'samedi'];
  filters = {
    specialite: '',
    adresse: '',
    term: ''
  };

  constructor(
    private router: Router,
    private authService: AuthService,
    private rdvService: RendezVousService,
    private alertCtrl: AlertController,
    private popoverController: PopoverController
  ) {}

  ngOnInit(): void {
    const user = this.authService.getUser();
    if (user) {
      this.isLoggedIn = true;
      this.userName = user.name || '';
      this.userRole = user.role || '';
    }
    this.loadMedecins();
  }

  ionViewWillEnter() {
    this.loadMedecins();
    const user = this.authService.getUser();
    if (user) {
      this.isLoggedIn = true;
      this.userName = user.name || '';
      this.userRole = user.role || '';
    } else {
      this.isLoggedIn = false;
      this.userName = '';
      this.userRole = '';
    }
  }

  loadMedecins() {
    this.rdvService.getMedecins().subscribe({
      next: (data: any[]) => {
        this.allMedecins = data.map(medecin => ({
          ...medecin,
          showDisponibilites: false
        }));
        this.medecins = [...this.allMedecins];
      },
      error: (err) => console.error('Erreur lors du chargement des médecins:', err)
    });
  }
  showFilters = false;
  toggleFilters() {
    this.showFilters = !this.showFilters;
  }
  filterMedecins() {
    const params = {
      specialite: this.filters.specialite.trim(),
      adresse: this.filters.adresse.trim(),
      term: this.filters.term.trim()
    };

    // Si aucun filtre n'est rempli, afficher tous les médecins
    if (!params.specialite && !params.adresse && !params.term) {
      this.medecins = [...this.allMedecins];
      return;
    }

    // Appeler la route de recherche avec les paramètres
    this.rdvService.searchMedecins(params).subscribe({
      next: (data: any[]) => {
        this.medecins = data.map(medecin => ({
          ...medecin,
          showDisponibilites: false
        }));
      },
      error: (err) => {
        console.error('Erreur lors du filtrage des médecins:', err);
        this.showAlert('Erreur', 'Impossible de filtrer les médecins.');
      }
    });
  }

  resetFilters() {
    this.filters = { specialite: '', adresse: '', term: '' };
    this.medecins = [...this.allMedecins];
  }

  toggleDisponibilites(medecin: any) {
    medecin.showDisponibilites = !medecin.showDisponibilites;
  }

  async prendreRendezVous(medecinId: string) {
    if (!this.isLoggedIn || this.userRole !== 'patient') {
      const alert = await this.alertCtrl.create({
        header: 'Erreur',
        message: 'Vous devez être connecté en tant que patient pour prendre un rendez-vous.',
        buttons: ['OK']
      });
      await alert.present();
      return;
    }
  
    const medecin = this.medecins.find(m => m.id === medecinId);
    if (!medecin) {
      const alert = await this.alertCtrl.create({
        header: 'Erreur',
        message: 'Médecin non trouvé.',
        buttons: ['OK']
      });
      await alert.present();
      return;
    }
  
    const joursDisponibles = Object.keys(medecin.disponibilites).filter(
      jour => this.validDays.includes(jour) && medecin.disponibilites[jour]?.length > 0
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
  
            const creneaux = medecin.disponibilites[selectedJour] || [];
            console.log(`Créneaux bruts pour ${selectedJour}:`, creneaux);
  
            // Filtrer les créneaux valides
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
              inputs: creneauxValides.map((creneau: any, index: number) => {
                const value = `${creneau.debut}|${creneau.fin}`; // Utiliser '|' comme séparateur
                console.log(`Créneau affiché: ${creneau.debut} - ${creneau.fin}, value: ${value}`);
                return {
                  name: 'creneau',
                  type: 'radio',
                  label: `${creneau.debut} - ${creneau.fin}`,
                  value: value
                };
              }),
              buttons: [
                { text: 'Annuler', role: 'cancel' },
                {
                  text: 'Confirmer',
                  handler: async (selectedCreneau: string) => {
                    console.log('SelectedCreneau:', selectedCreneau);
  
                    if (!selectedCreneau) {
                      const errorAlert = await this.alertCtrl.create({
                        header: 'Erreur',
                        message: 'Veuillez sélectionner un créneau.',
                        buttons: ['OK']
                      });
                      await errorAlert.present();
                      return false;
                    }
  
                    // Valider et normaliser les horaires
                    const times = selectedCreneau.split('|'); // Diviser sur '|'
                    if (times.length !== 2) {
                      console.error('Invalid times split:', times);
                      const errorAlert = await this.alertCtrl.create({
                        header: 'Erreur',
                        message: 'Créneau invalide sélectionné.',
                        buttons: ['OK']
                      });
                      await errorAlert.present();
                      return false;
                    }
  
                    const [debutRaw, finRaw] = times;
                    const debutMatch = debutRaw.match(/^(\d{1,2}):(\d{2})$/);
                    const finMatch = finRaw.match(/^(\d{1,2}):(\d{2})$/);
  
                    if (!debutMatch || !finMatch) {
                      console.error('Regex failed - debutRaw:', debutRaw, 'finRaw:', finRaw);
                      const errorAlert = await this.alertCtrl.create({
                        header: 'Erreur',
                        message: 'Format horaire invalide.',
                        buttons: ['OK']
                      });
                      await errorAlert.present();
                      return false;
                    }
  
                    const debut = `${parseInt(debutMatch[1]).toString().padStart(2, '0')}:${debutMatch[2]}`;
                    const fin = `${parseInt(finMatch[1]).toString().padStart(2, '0')}:${finMatch[2]}`;
  
                    const rdv = {
                      medecinId: medecinId,
                      jour: selectedJour.toLowerCase(),
                      debut: debut,
                      fin: fin
                    };
  
                    console.log('Envoi de la requête rendez-vous:', rdv);
  
                    this.rdvService.prendreRendezVous(rdv).subscribe({
                      next: async () => {
                        const successAlert = await this.alertCtrl.create({
                          header: 'Succès',
                          message: 'Rendez-vous pris avec succès !',
                          buttons: ['OK']
                        });
                        await successAlert.present();
                        this.loadMedecins();
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

  goToPage(route: string) {
    this.router.navigate([route]);
  }
}