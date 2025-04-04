import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { RendezVousService } from '../../services/rendez-vous.service';
import { AppComponent } from 'src/app/app.component';
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
  searchTerm: string = '';
  medecins: any[] = [];
  allMedecins: any[] = [];

  // Liste des jours valides
  readonly validDays = ['lundi', 'mardi', 'mercredi', 'jeudi', 'vendredi', 'samedi'];

  quickAccess = [
    { name: 'Rechercher un médecin', icon: 'search-outline', route: '/search' },
    { name: 'Prendre un RDV', icon: 'calendar-outline', route: '/appointments' },
    { name: 'Mes documents', icon: 'document-text-outline', route: '/documents' },
    { name: 'Profil', icon: 'person-outline', route: '/profile' },
    { name: 'Paramètres', icon: 'settings-outline', route: '/settings' },
  ];

  constructor(
    private router: Router,
    private authService: AuthService,
    private rdvService: RendezVousService,
    private appComponent: AppComponent,
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
        this.allMedecins = data || [];
        this.medecins = [...this.allMedecins];
      },
      error: (err) => console.error('Erreur lors du chargement des médecins:', err)
    });
  }

  filterMedecins() {
    const term = this.searchTerm.toLowerCase().trim();
    if (!term) {
      this.medecins = [...this.allMedecins];
      return;
    }

    this.medecins = this.allMedecins.filter(medecin => {
      const name = (medecin.name || '').toString().toLowerCase();
      const specialite = (medecin.specialite || '').toString().toLowerCase();
      const email = (medecin.email || '').toString().toLowerCase();
      const sexe = (medecin.sexe || '').toString().toLowerCase();
      const etab = (medecin.etab || '').toString().toLowerCase();
      const faculte = (medecin.faculte || '').toString().toLowerCase();
      const adresse = (medecin.adresse || '').toString().toLowerCase();
      const tel = (medecin.tel || '').toString().toLowerCase();
      const gsm = (medecin.gsm || '').toString().toLowerCase();

      return (
        name.includes(term) ||
        specialite.includes(term) ||
        email.includes(term) ||
        sexe.includes(term) ||
        etab.includes(term) ||
        faculte.includes(term) ||
        adresse.includes(term) ||
        tel.includes(term) ||
        gsm.includes(term)
      );
    });
  }



  goToPage(route: string) {
    this.router.navigate([route]);
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

    const alert = await this.alertCtrl.create({
      header: 'Prendre un rendez-vous',
      inputs: [
        {
          name: 'jour',
          type: 'text',
          placeholder: 'Jour (ex: lundi)'
        },
        {
          name: 'debut',
          type: 'time',
          placeholder: 'Heure de début'
        },
        {
          name: 'fin',
          type: 'time',
          placeholder: 'Heure de fin'
        }
      ],
      buttons: [
        { text: 'Annuler', role: 'cancel' },
        {
          text: 'Confirmer',
          handler: async (data: any) => {
            const jour = data.jour.toLowerCase().trim();
            const debut = data.debut;
            const fin = data.fin;

            // Validation des champs
            if (!jour || !debut || !fin) {
              const errorAlert = await this.alertCtrl.create({
                header: 'Erreur',
                message: 'Tous les champs doivent être remplis.',
                buttons: ['OK']
              });
              await errorAlert.present();
              return false;
            }

            // Validation du jour
            if (!this.validDays.includes(jour)) {
              const errorAlert = await this.alertCtrl.create({
                header: 'Erreur',
                message: 'Le jour doit être valide (lundi, mardi, mercredi, jeudi, vendredi, samedi).',
                buttons: ['OK']
              });
              await errorAlert.present();
              return false;
            }

            // Vérification des disponibilités du médecin
            const disponibilites = medecin.disponibilites[jour] || [];
            if (disponibilites.length === 0) {
              const errorAlert = await this.alertCtrl.create({
                header: 'Erreur',
                message: `Le médecin n'est pas disponible le ${jour}.`,
                buttons: ['OK']
              });
              await errorAlert.present();
              return false;
            }

            const isAvailable = disponibilites.some((creneau: any) => {
              const creneauDebut = this.timeToMinutes(creneau.debut);
              const creneauFin = this.timeToMinutes(creneau.fin);
              const rdvDebut = this.timeToMinutes(debut);
              const rdvFin = this.timeToMinutes(fin);

              return rdvDebut >= creneauDebut && rdvFin <= creneauFin && rdvDebut < rdvFin;
            });

            if (!isAvailable) {
              const errorAlert = await this.alertCtrl.create({
                header: 'Erreur',
                message: `Le créneau ${debut}-${fin} n'est pas disponible le ${jour} pour ce médecin.`,
                buttons: ['OK']
              });
              await errorAlert.present();
              return false;
            }

            // Si tout est valide, enregistrer le rendez-vous
            const rdv = {
              medecinId: medecinId,
              jour: jour,
              debut: debut,
              fin: fin
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
                const errorAlert = await this.alertCtrl.create({
                  header: 'Erreur',
                  message: err.error?.message || 'Erreur lors de la prise de rendez-vous',
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
    await alert.present();
  }

  // Utilitaire pour convertir une heure (HH:mm) en minutes
  private timeToMinutes(time: string): number {
    const [hours, minutes] = time.split(':').map(Number);
    return hours * 60 + minutes;
  }
}