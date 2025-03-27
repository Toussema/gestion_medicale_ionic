import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { AppComponent } from 'src/app/app.component';



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

  // Carrousel des images/publicités
  pubs: string[] = [
    'assets/images/pub1.jpg',
    'assets/images/pub2.jpg',
    'assets/images/pub3.jpg',
  ];

  // Liste des fonctionnalités pour les patients et médecins
  quickAccess = [
    { name: 'Rechercher un médecin', icon: 'search-outline', route: '/search' },
    { name: 'Prendre un RDV', icon: 'calendar-outline', route: '/appointments' },
    { name: 'Mes documents', icon: 'document-text-outline', route: '/documents' },
    { name: 'Profil', icon: 'person-outline', route: '/profile' },
    { name: 'Paramètres', icon: 'settings-outline', route: '/settings' },
  ];

  constructor(private router: Router, private authService: AuthService, private appComponent: AppComponent) {}

  ngOnInit(): void {
    const user = this.authService.getUser();
  }

 /* Ouvre le menu profil. */
  openProfileMenu(event: Event) {
    this.appComponent.openProfileMenu(event);
  } 

  goToPage(route: string) {
    this.router.navigate([route]);
  }

  /*goToDashboard() {
    if (this.userRole === 'patient') {
      this.router.navigate(['/espace-patient']);
    } else if (this.userRole === 'medecin') {
      this.router.navigate(['/espace-medecin']);
    }
  }*/
  

  

  
}