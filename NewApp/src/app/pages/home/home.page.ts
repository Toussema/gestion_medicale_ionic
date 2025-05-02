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
    gouvernorat: '',
    ville: '',
    term: ''
  };
  specialites: string[] = [];
  gouvernorats: string[] = [];
  villes: string[] = [];
  showFilters = false;
  selectedDay: string | null = null;


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
    this.loadFilterOptions();
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
          showDisponibilites: false,
          disponibilites: medecin.disponibilites || {}
        }));
        this.medecins = [...this.allMedecins];
      },
      error: (err) => {
        console.error('Erreur lors du chargement des médecins:', err);
        this.showAlert('Erreur', 'Impossible de charger la liste des médecins.');
      }
    });
  }
  viewMedecinDetails(medecinId: string) {
    this.router.navigate(['/medecin-detail', medecinId]);
  }

  loadFilterOptions() {
    this.rdvService.getSpecialites().subscribe({
      next: (data) => this.specialites = data,
      error: (err) => console.error('Erreur lors du chargement des spécialités:', err)
    });
    this.rdvService.getGouvernorats().subscribe({
      next: (data) => this.gouvernorats = data,
      error: (err) => console.error('Erreur lors du chargement des gouvernorats:', err)
    });
    this.rdvService.getVilles().subscribe({
      next: (data) => this.villes = data,
      error: (err) => console.error('Erreur lors du chargement des villes:', err)
    });
  }

  toggleFilters() {
    this.showFilters = !this.showFilters;
  }

  filterMedecins() {
    const params = {
      specialite: this.filters.specialite.trim(),
      gouvernorat: this.filters.gouvernorat.trim(),
      ville: this.filters.ville.trim(),
      term: this.filters.term.trim()
    };

    if (!params.specialite && !params.gouvernorat && !params.ville && !params.term) {
      this.medecins = [...this.allMedecins];
      return;
    }

    this.rdvService.searchMedecins(params).subscribe({
      next: (data: any[]) => {
        this.medecins = data.map(medecin => ({
          ...medecin,
          showDisponibilites: false,
          disponibilites: medecin.disponibilites || {}
        }));
      },
      error: (err) => {
        console.error('Erreur lors du filtrage des médecins:', err);
        this.showAlert('Erreur', 'Impossible de filtrer les médecins.');
      }
    });
  }

  resetFilters() {
    this.filters = { specialite: '', gouvernorat: '', ville: '', term: '' };
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

  toggleDaySelection(jour: string) {
    if (this.selectedDay === jour) {
      this.selectedDay = null;
    } else {
      this.selectedDay = jour;
    }
  }
}